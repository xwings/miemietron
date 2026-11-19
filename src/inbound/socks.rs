//! SOCKS5 proxy inbound listener.
//!
//! Implements RFC 1928 (SOCKS5) with no-auth and username/password (RFC 1929)
//! authentication methods. Supports CONNECT (TCP) and UDP ASSOCIATE commands.
//! UDP datagrams are routed through the ConnectionManager's rule engine.

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::conn::{
    udp::{self, UdpInbound, UdpPacket},
    ConnectionManager,
};
use tokio::sync::mpsc;

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Start a SOCKS5 proxy listener on `addr`.
pub async fn run_socks_proxy(
    addr: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth: Arc<Vec<String>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let _udp = UdpListener::start(addr, conn_manager.clone()).await?;
    tracing::info!("SOCKS5 proxy listening on {}", addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("SOCKS5 accept error: {}", e);
                continue;
            }
        };
        crate::transport::tcp::apply_inbound_keepalive(&stream);

        let cm = conn_manager.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(stream, peer, cm, &auth).await {
                debug!("SOCKS5 connection from {} ended: {}", peer, e);
            }
        });
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth_list: &[String],
) -> Result<()> {
    let require_auth = !auth_list.is_empty();

    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        return Err(anyhow!("unsupported SOCKS version: {version}"));
    }

    let n_methods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    let chosen = if require_auth {
        // When authentication is configured, require username/password
        if methods.contains(&AUTH_USER_PASS) {
            AUTH_USER_PASS
        } else {
            stream
                .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
                .await?;
            return Err(anyhow!("client does not support required auth method"));
        }
    } else {
        // No authentication configured: prefer no-auth, fall back to user/pass
        if methods.contains(&AUTH_NONE) {
            AUTH_NONE
        } else if methods.contains(&AUTH_USER_PASS) {
            AUTH_USER_PASS
        } else {
            stream
                .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
                .await?;
            return Err(anyhow!("no acceptable auth method"));
        }
    };

    stream.write_all(&[SOCKS5_VERSION, chosen]).await?;

    // Handle username/password sub-negotiation (RFC 1929)
    if chosen == AUTH_USER_PASS {
        let sub_ver = stream.read_u8().await?;
        if sub_ver != 0x01 {
            return Err(anyhow!("bad user/pass sub-negotiation version"));
        }
        let ulen = stream.read_u8().await? as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;
        let plen = stream.read_u8().await? as usize;
        let mut passwd = vec![0u8; plen];
        stream.read_exact(&mut passwd).await?;

        let username = String::from_utf8_lossy(&uname);
        let password = String::from_utf8_lossy(&passwd);

        if require_auth {
            // Validate against the configured authentication list
            // Each entry is "username:password"
            let credential = format!("{username}:{password}");
            if !auth_list.iter().any(|entry| entry == &credential) {
                stream.write_all(&[0x01, 0x01]).await?; // failure
                return Err(anyhow!(
                    "SOCKS5 auth failed for user '{username}' from {peer}"
                ));
            }
        }

        stream.write_all(&[0x01, 0x00]).await?; // success
    }

    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(anyhow!("unexpected version in request: {ver}"));
    }
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved
    let atyp = stream.read_u8().await?;

    let (host, port) = read_address(&mut stream, atyp).await?;

    // Build dst SocketAddr and host_override (for domain targets)
    let (dst, host_override) = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => (SocketAddr::new(ip, port), None),
        // Domain target — use placeholder IP, pass domain via host_override
        Err(_) => (
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            Some(host),
        ),
    };

    // mihomo compat: transport/socks5 ServerHandshake — BND.ADDR is the
    // address this connection was accepted on, for CONNECT and for UDP
    // ASSOCIATE alike. The UDP relay listens on the same port.
    let bound = stream.local_addr()?;
    let bound = SocketAddr::new(bound.ip().to_canonical(), bound.port());

    match cmd {
        CMD_CONNECT => {
            send_reply(&mut stream, REP_SUCCESS, &bound).await?;

            conn_manager
                .handle_tcp_with_host(peer, dst, stream, "socks5", host_override)
                .await?;
        }
        CMD_UDP_ASSOCIATE => {
            send_reply(&mut stream, REP_SUCCESS, &bound).await?;
            // mihomo compat: listener/socks/tcp.go — the connection is only
            // held open until the client closes it. The UDP sessions do not
            // depend on it; they end when they go idle.
            let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
        }
        _ => {
            send_reply(&mut stream, REP_CMD_NOT_SUPPORTED, &dst).await?;
            return Err(anyhow!("unsupported SOCKS5 command: {cmd}"));
        }
    }

    Ok(())
}

/// The UDP side of a SOCKS5 or mixed listener.
///
/// mihomo compat: listener/socks/udp.go — one socket on the listener's own
/// address serves every client. A session belongs to the address a client
/// sends from (the NAT key), not to the TCP connection that asked for the
/// association.
pub struct UdpListener {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for UdpListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl UdpListener {
    pub async fn start(addr: SocketAddr, conn_manager: Arc<ConnectionManager>) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Ok(Self {
            task: tokio::spawn(relay_udp(socket, conn_manager)),
        })
    }
}

async fn relay_udp(socket: Arc<UdpSocket>, conn_manager: Arc<ConnectionManager>) {
    let nat_table: Arc<DashMap<SocketAddr, mpsc::Sender<UdpPacket>>> = Arc::new(DashMap::new());
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("SOCKS5 UDP receive error: {}", e);
                continue;
            }
        };
        let src = SocketAddr::new(src.ip().to_canonical(), src.port());
        let Some(packet) = decode_udp_packet(&buf[..n]) else {
            continue;
        };
        let Some((tx, rx)) = udp::enqueue(&nat_table, src, packet) else {
            continue;
        };
        let cm = conn_manager.clone();
        let nat = nat_table.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let session = cm.handle_udp(
                UdpInbound {
                    src,
                    conn_type: "socks5",
                },
                rx,
                |data, from| {
                    let socket = &socket;
                    async move {
                        socket.send_to(&encode_udp_packet(from, &data), src).await?;
                        Ok(())
                    }
                },
            );
            if let Err(error) = session.await {
                debug!("SOCKS5 UDP session {} error: {}", src, error);
            }
            nat.remove_if(&src, |_, existing| existing.same_channel(&tx));
        });
    }
}

/// mihomo compat: transport/socks5 `DecodeUDPPacket` — RSV(2) FRAG(1)
/// ATYP(1) DST.ADDR DST.PORT(2) DATA. Reserved bytes must be zero and
/// fragments are discarded.
fn decode_udp_packet(packet: &[u8]) -> Option<UdpPacket> {
    if packet.len() < 5 || packet[..3] != [0, 0, 0] {
        return None;
    }
    let body = &packet[3..];
    let port_at = match body[0] {
        ATYP_IPV4 => 1 + 4,
        ATYP_DOMAIN => 1 + 1 + body[1] as usize,
        ATYP_IPV6 => 1 + 16,
        _ => return None,
    };
    let port = u16::from_be_bytes(body.get(port_at..port_at + 2)?.try_into().ok()?);
    let (ip, host) = match body[0] {
        ATYP_IPV4 => {
            let octets: [u8; 4] = body[1..5].try_into().ok()?;
            (IpAddr::from(octets), None)
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = body[1..17].try_into().ok()?;
            (IpAddr::from(octets), None)
        }
        _ => {
            let host = String::from_utf8_lossy(&body[2..port_at]).to_string();
            match host.parse::<IpAddr>() {
                // mihomo compat: tunnel.go fixMetadata — an address written
                // as a name is an address.
                Ok(ip) => (ip, None),
                Err(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(host)),
            }
        }
    };
    Some(UdpPacket {
        dst: SocketAddr::new(ip.to_canonical(), port),
        host,
        data: body[port_at + 2..].to_vec(),
    })
}

/// mihomo compat: listener/socks/utils.go `WriteBack` — the header names the
/// address the datagram came from.
fn encode_udp_packet(from: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(3 + 19 + data.len());
    packet.extend_from_slice(&[0, 0, 0]);
    match from.ip() {
        IpAddr::V4(ip) => {
            packet.push(ATYP_IPV4);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(ATYP_IPV6);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&from.port().to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Read a SOCKS5 address (ATYP + addr + port).
async fn read_address(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = stream.read_u16().await?;
            Ok((ip.to_string(), port))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf)?;
            let port = stream.read_u16().await?;
            Ok((domain, port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv6Addr::from(buf);
            let port = stream.read_u16().await?;
            Ok((ip.to_string(), port))
        }
        _ => Err(anyhow!("unsupported SOCKS5 address type: {atyp}")),
    }
}

/// Send a SOCKS5 reply.
async fn send_reply<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    rep: u8,
    bind_addr: &SocketAddr,
) -> Result<()> {
    let mut buf = Vec::with_capacity(32);
    buf.push(SOCKS5_VERSION);
    buf.push(rep);
    buf.push(0x00); // reserved

    match bind_addr {
        SocketAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    stream.write_all(&buf).await?;
    Ok(())
}

/// Handle a single already-accepted SOCKS5 connection (used by the mixed-port
/// listener).
pub async fn run_socks_single(
    stream: TcpStream,
    peer: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth: Arc<Vec<String>>,
) -> Result<()> {
    handle_socks5(stream, peer, conn_manager, &auth).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn socks5_constants_match_rfc1928() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(AUTH_NONE, 0x00);
        assert_eq!(AUTH_USER_PASS, 0x02);
        assert_eq!(AUTH_NO_ACCEPTABLE, 0xFF);
        assert_eq!(CMD_CONNECT, 0x01);
        assert_eq!(CMD_UDP_ASSOCIATE, 0x03);
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
        assert_eq!(REP_SUCCESS, 0x00);
        assert_eq!(REP_CMD_NOT_SUPPORTED, 0x07);
    }

    #[tokio::test]
    async fn send_reply_ipv4_format() {
        // In-memory duplex stream — no privileged socket bind, no env-flake.
        let (mut client, mut server) = tokio::io::duplex(64);

        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1080));
        send_reply(&mut server, REP_SUCCESS, &bind).await.unwrap();

        let mut buf = vec![0u8; 32];
        let n = client.read(&mut buf).await.unwrap();
        // Expected: version(5) + rep(0) + rsv(0) + atyp(1) + ip(4 bytes) + port(2 bytes)
        assert_eq!(n, 10);
        assert_eq!(buf[0], SOCKS5_VERSION);
        assert_eq!(buf[1], REP_SUCCESS);
        assert_eq!(buf[2], 0x00); // reserved
        assert_eq!(buf[3], ATYP_IPV4);
        assert_eq!(&buf[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([buf[8], buf[9]]), 1080);
    }

    #[test]
    fn udp_packets_are_decoded_like_mihomo() {
        // transport/socks5 DecodeUDPPacket.
        let v4 = [0, 0, 0, ATYP_IPV4, 8, 8, 4, 4, 0, 53, b'h', b'i'];
        assert_eq!(
            decode_udp_packet(&v4),
            Some(UdpPacket::new(
                "8.8.4.4:53".parse().unwrap(),
                b"hi".to_vec()
            ))
        );

        let mut v6 = vec![0, 0, 0, ATYP_IPV6];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0x01, 0xbb, 1, 2, 3]);
        assert_eq!(
            decode_udp_packet(&v6),
            Some(UdpPacket::new("[::1]:443".parse().unwrap(), vec![1, 2, 3]))
        );

        let mut named = vec![0, 0, 0, ATYP_DOMAIN, 11];
        named.extend_from_slice(b"example.com");
        named.extend_from_slice(&[0, 80]);
        assert_eq!(
            decode_udp_packet(&named),
            Some(UdpPacket {
                dst: "0.0.0.0:80".parse().unwrap(),
                host: Some("example.com".to_string()),
                data: Vec::new(),
            })
        );

        // tunnel.go fixMetadata: an address spelled as a name is an address.
        let mut literal = vec![0, 0, 0, ATYP_DOMAIN, 7];
        literal.extend_from_slice(b"1.2.3.4");
        literal.extend_from_slice(&[0, 80, 9]);
        assert_eq!(
            decode_udp_packet(&literal),
            Some(UdpPacket::new("1.2.3.4:80".parse().unwrap(), vec![9]))
        );

        // Reserved bytes must be zero, fragments are discarded, and a header
        // that does not fit is no packet.
        assert_eq!(
            decode_udp_packet(&[0, 1, 0, ATYP_IPV4, 8, 8, 4, 4, 0, 53]),
            None
        );
        assert_eq!(
            decode_udp_packet(&[0, 0, 1, ATYP_IPV4, 8, 8, 4, 4, 0, 53]),
            None
        );
        assert_eq!(
            decode_udp_packet(&[0, 0, 0, ATYP_IPV4, 8, 8, 4, 4, 0]),
            None
        );
        assert_eq!(decode_udp_packet(&[0, 0, 0, 9, 8, 8, 4, 4, 0, 53]), None);
        assert_eq!(
            decode_udp_packet(&[0, 0, 0, ATYP_DOMAIN, 200, b'a', 0, 53]),
            None
        );
    }

    /// Run the SOCKS5 greeting and a UDP ASSOCIATE on `control`, returning
    /// BND.ADDR:BND.PORT.
    async fn associate(control: &mut TcpStream) -> SocketAddr {
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut choice = [0u8; 2];
        control.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [5, 0]);
        control
            .write_all(&[5, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, REP_SUCCESS, 0, ATYP_IPV4]);
        SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        ))
    }

    #[tokio::test]
    async fn udp_associate_relays_on_the_listener_port_with_real_reply_sources() {
        // mihomo: `socks.NewUDP` on the listener's address; BND is the TCP
        // connection's local address; replies name where they came from; the
        // association outlives nothing but itself.
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = reserve.local_addr().unwrap();
        drop(reserve);
        let cm = Arc::new(crate::conn::test_support::manager("rules: ['MATCH,DIRECT']\n").await);
        let server = tokio::spawn(run_socks_proxy(listen, cm, Arc::new(Vec::new())));

        let mut control = loop {
            match TcpStream::connect(listen).await {
                Ok(stream) => break stream,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        assert_eq!(associate(&mut control).await, listen);

        let echo_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 256];
        let mut outbound = None;
        for (echo, by_name) in [(&echo_a, false), (&echo_b, true)] {
            let target = echo.local_addr().unwrap();
            let mut request = vec![0, 0, 0];
            if by_name {
                request.extend_from_slice(&[ATYP_DOMAIN, 9]);
                request.extend_from_slice(b"localhost");
            } else {
                request.extend_from_slice(&[ATYP_IPV4, 127, 0, 0, 1]);
            }
            request.extend_from_slice(&target.port().to_be_bytes());
            request.extend_from_slice(b"ping");
            client.send_to(&request, listen).await.unwrap();

            let (n, from) =
                tokio::time::timeout(std::time::Duration::from_secs(5), echo.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buf[..n], b"ping");
            // One outbound socket for the client, whatever it sends to.
            assert_eq!(*outbound.get_or_insert(from), from);

            echo.send_to(b"pong", from).await.unwrap();
            let (n, relay) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(relay, listen);
            // The reply names the address it came from, also when the
            // request named a host.
            assert_eq!(&buf[..n], encode_udp_packet(target, b"pong"));
        }
        server.abort();
    }

    #[tokio::test]
    async fn send_reply_ipv6_format() {
        let (mut client, mut server) = tokio::io::duplex(64);

        let bind = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 9090);
        send_reply(&mut server, REP_SUCCESS, &bind).await.unwrap();

        let mut buf = vec![0u8; 32];
        let n = client.read(&mut buf).await.unwrap();
        // Expected: version(5) + rep(0) + rsv(0) + atyp(4) + ip(16 bytes) + port(2 bytes)
        assert_eq!(n, 22);
        assert_eq!(buf[0], SOCKS5_VERSION);
        assert_eq!(buf[1], REP_SUCCESS);
        assert_eq!(buf[3], ATYP_IPV6);
        assert_eq!(u16::from_be_bytes([buf[20], buf[21]]), 9090);
    }
}
