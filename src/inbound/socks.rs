//! SOCKS5 proxy inbound listener.
//!
//! Implements RFC 1928 (SOCKS5) with no-auth and username/password (RFC 1929)
//! authentication methods. Supports CONNECT (TCP) and UDP ASSOCIATE commands.
//! UDP datagrams are routed through the ConnectionManager's rule engine.

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::common::addr::Address;
use crate::conn::{
    udp::{self, UdpInbound},
    ConnectionManager,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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

    match cmd {
        CMD_CONNECT => {
            // Send success reply
            send_reply(&mut stream, REP_SUCCESS, &dst).await?;

            conn_manager
                .handle_tcp_with_host(peer, dst, stream, "socks5", host_override)
                .await?;
        }
        CMD_UDP_ASSOCIATE => {
            // Bind a UDP socket for the SOCKS5 UDP relay
            let udp_socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
            let bound_addr = udp_socket.local_addr()?;
            debug!("SOCKS5 UDP ASSOCIATE: bound to {}", bound_addr);

            // Report the bound address to the client
            send_reply(&mut stream, REP_SUCCESS, &bound_addr).await?;

            // Per-session NAT table: keyed by (client_addr, target) to reuse
            // OutboundPacketConn across datagrams to the same destination.
            let nat_table: Arc<DashMap<(SocketAddr, Address), mpsc::Sender<Vec<u8>>>> =
                Arc::new(DashMap::new());
            let timeout_dur = Duration::from_secs(60);

            let cancelled = CancellationToken::new();
            let relay_cancelled = cancelled.clone();

            // Spawn the main UDP relay task
            let cm = conn_manager.clone();
            let relay_handle = tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    let (n, src) = match udp_socket.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if n < 10 {
                        continue; // Too short for SOCKS5 UDP header
                    }

                    // Parse SOCKS5 UDP request header (RFC 1928 section 7):
                    // RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2) + DATA
                    let _rsv = u16::from_be_bytes([buf[0], buf[1]]);
                    let frag = buf[2];
                    if frag != 0 {
                        continue; // Fragmentation not supported
                    }

                    // Parse the header once into the target Address plus the
                    // SocketAddr used for rule-engine resolution (UNSPECIFIED
                    // placeholder for domain targets).
                    let atyp = buf[3];
                    let (target, dst_sockaddr, data_offset) = match atyp {
                        ATYP_IPV4 if n >= 10 => {
                            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                            let port = u16::from_be_bytes([buf[8], buf[9]]);
                            let sa = SocketAddr::new(ip.into(), port);
                            (Address::ip(sa), sa, 10)
                        }
                        ATYP_DOMAIN if n > 5 => {
                            let dlen = buf[4] as usize;
                            if n < 5 + dlen + 2 {
                                continue;
                            }
                            let host = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
                            let port = u16::from_be_bytes([buf[5 + dlen], buf[6 + dlen]]);
                            (
                                Address::Domain(host, port),
                                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                                7 + dlen,
                            )
                        }
                        ATYP_IPV6 if n >= 22 => {
                            let ip = Ipv6Addr::from([
                                buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
                                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18],
                                buf[19],
                            ]);
                            let port = u16::from_be_bytes([buf[20], buf[21]]);
                            let sa = SocketAddr::new(ip.into(), port);
                            (Address::ip(sa), sa, 22)
                        }
                        _ => continue,
                    };

                    let data = buf[data_offset..n].to_vec();

                    debug!(
                        "SOCKS5 UDP relay: {} -> {} ({} bytes)",
                        src,
                        target,
                        data.len()
                    );

                    let nat_key = (src, target.clone());

                    // Register the queue before spawning the worker. All
                    // fragments of a handshake must reach the same sniffer.
                    let Some((tx, rx)) = udp::enqueue(&nat_table, nat_key.clone(), data) else {
                        continue;
                    };
                    let cm = cm.clone();
                    let nat = nat_table.clone();
                    let socket = udp_socket.clone();
                    let cancel = relay_cancelled.clone();
                    let header = buf[3..data_offset].to_vec();
                    let domain = match target {
                        Address::Domain(host, _) => Some(host),
                        Address::Ip(_) => None,
                    };
                    tokio::spawn(async move {
                        let relay = cm.handle_udp(
                            UdpInbound {
                                src,
                                dst: dst_sockaddr,
                                conn_type: "socks5",
                                domain,
                            },
                            rx,
                            timeout_dur,
                            |data| {
                                let socket = socket.clone();
                                let mut response =
                                    Vec::with_capacity(3 + header.len() + data.len());
                                response.extend_from_slice(&[0, 0, 0]);
                                response.extend_from_slice(&header);
                                response.extend_from_slice(&data);
                                async move {
                                    socket.send_to(&response, src).await?;
                                    Ok(())
                                }
                            },
                        );
                        tokio::select! {
                            result = relay => if let Err(error) = result { debug!("SOCKS5 UDP session {} error: {}", src, error); },
                            _ = cancel.cancelled() => {},
                        }
                        nat.remove_if(&nat_key, |_, existing| existing.same_channel(&tx));
                    });
                }
            });

            // Keep TCP control connection alive; when it closes, abort the relay
            let mut ctrl_buf = [0u8; 1];
            let _ = stream.read(&mut ctrl_buf).await;
            relay_handle.abort();
            cancelled.cancel();
        }
        _ => {
            send_reply(&mut stream, REP_CMD_NOT_SUPPORTED, &dst).await?;
            return Err(anyhow!("unsupported SOCKS5 command: {cmd}"));
        }
    }

    Ok(())
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
