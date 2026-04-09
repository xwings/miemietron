//! SOCKS5 proxy inbound listener.
//!
//! Implements RFC 1928 (SOCKS5) with no-auth and username/password (RFC 1929)
//! authentication methods. Supports CONNECT (TCP) and UDP ASSOCIATE commands.
//! UDP datagrams are routed through the ConnectionManager's rule engine.

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::common::addr::Address;
use crate::conn::ConnectionManager;
use crate::proxy::OutboundPacketConn;
use crate::rules::Action;

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
    let (dst, host_override) = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        (SocketAddr::new(ip, port), None)
    } else {
        // Domain target — use placeholder IP, pass domain via host_override
        (
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            Some(host.clone()),
        )
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
            let nat_table: Arc<DashMap<(SocketAddr, Address), SocksUdpSession>> =
                Arc::new(DashMap::new());
            let timeout_dur = Duration::from_secs(60);

            // Spawn a reaper task to clean up idle sessions
            let reaper_table = nat_table.clone();
            let reaper_handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    reaper_table
                        .retain(|_key, session: &mut SocksUdpSession| {
                            now.duration_since(session.last_active) < Duration::from_secs(60)
                        });
                }
            });

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

                    let atyp = buf[3];
                    let (host, port, data_offset) = match atyp {
                        ATYP_IPV4 if n >= 10 => {
                            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                            let port = u16::from_be_bytes([buf[8], buf[9]]);
                            (ip.to_string(), port, 10)
                        }
                        ATYP_DOMAIN if n > 5 => {
                            let dlen = buf[4] as usize;
                            if n < 5 + dlen + 2 {
                                continue;
                            }
                            let host =
                                String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
                            let port =
                                u16::from_be_bytes([buf[5 + dlen], buf[6 + dlen]]);
                            (host, port, 7 + dlen)
                        }
                        ATYP_IPV6 if n >= 22 => {
                            let ip = Ipv6Addr::from([
                                buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                                buf[10], buf[11], buf[12], buf[13], buf[14],
                                buf[15], buf[16], buf[17], buf[18], buf[19],
                            ]);
                            let port = u16::from_be_bytes([buf[20], buf[21]]);
                            (ip.to_string(), port, 22)
                        }
                        _ => continue,
                    };

                    let data = buf[data_offset..n].to_vec();
                    // Save the raw SOCKS5 header (atyp + addr portion) for building
                    // response headers on the reverse path.
                    let header_bytes = buf[3..data_offset].to_vec();

                    debug!(
                        "SOCKS5 UDP relay: {} -> {}:{} ({} bytes)",
                        src,
                        host,
                        port,
                        data.len()
                    );

                    // Build target Address from parsed host/port
                    let target = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        Address::ip(SocketAddr::new(ip, port))
                    } else {
                        Address::domain(&host, port)
                    };

                    // Build a SocketAddr for rule engine resolution.
                    // For domain targets, use UNSPECIFIED as placeholder IP.
                    let dst_sockaddr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                        SocketAddr::new(ip, port)
                    } else {
                        SocketAddr::new(
                            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            port,
                        )
                    };

                    let nat_key = (src, target.clone());

                    // Check if we already have a session for this (src, target) pair
                    if let Some(mut session) = nat_table.get_mut(&nat_key) {
                        session.last_active = Instant::now();
                        let pc = session.outbound.clone();
                        let target_clone = target.clone();
                        tokio::spawn(async move {
                            if let Err(e) = pc.send_to(&data, &target_clone).await {
                                debug!("SOCKS5 UDP send error: {}", e);
                            }
                        });
                        continue;
                    }

                    // New session: resolve action through rule engine and create
                    // OutboundPacketConn
                    let cm_ref = cm.clone();
                    let nat_ref = nat_table.clone();
                    let sock_ref = udp_socket.clone();

                    tokio::spawn(async move {
                        match create_socks_udp_session(
                            src,
                            dst_sockaddr,
                            &data,
                            &target,
                            &cm_ref,
                        )
                        .await
                        {
                            Ok(outbound) => {
                                let pc_rev = outbound.clone();
                                nat_ref.insert(
                                    nat_key.clone(),
                                    SocksUdpSession {
                                        outbound,
                                        last_active: Instant::now(),
                                    },
                                );

                                // Spawn reverse-path relay: outbound -> client
                                let nat_rev = nat_ref.clone();
                                let nat_key_rev = nat_key;
                                let header_for_reply = header_bytes;
                                tokio::spawn(async move {
                                    let mut rbuf = vec![0u8; 65535];
                                    loop {
                                        let recv = tokio::time::timeout(
                                            timeout_dur,
                                            pc_rev.recv_from(&mut rbuf),
                                        )
                                        .await;

                                        match recv {
                                            Ok(Ok((rn, _from))) => {
                                                if rn == 0 {
                                                    break;
                                                }
                                                // Update last_active timestamp
                                                if let Some(mut s) =
                                                    nat_rev.get_mut(&nat_key_rev)
                                                {
                                                    s.last_active = Instant::now();
                                                }
                                                // Build SOCKS5 UDP response:
                                                // RSV(0x0000) + FRAG(0x00) + ATYP + ADDR + PORT + DATA
                                                let mut reply = Vec::with_capacity(
                                                    3 + header_for_reply.len() + rn,
                                                );
                                                reply.extend_from_slice(&[0, 0, 0]); // RSV + FRAG
                                                reply.extend_from_slice(
                                                    &header_for_reply,
                                                ); // ATYP + addr + port
                                                reply.extend_from_slice(&rbuf[..rn]);
                                                if let Err(e) =
                                                    sock_ref.send_to(&reply, src).await
                                                {
                                                    debug!(
                                                        "SOCKS5 UDP reverse send error: {}",
                                                        e
                                                    );
                                                    break;
                                                }
                                            }
                                            Ok(Err(e)) => {
                                                debug!(
                                                    "SOCKS5 UDP proxy recv error: {}",
                                                    e
                                                );
                                                break;
                                            }
                                            Err(_) => {
                                                debug!(
                                                    "SOCKS5 UDP session {} -> {}:{} timed out",
                                                    src, host, port
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    nat_rev.remove(&nat_key_rev);
                                });
                            }
                            Err(e) => {
                                debug!(
                                    "SOCKS5 UDP session creation failed for {} -> {}:{}: {}",
                                    src, host, port, e
                                );
                            }
                        }
                    });
                }
            });

            // Keep TCP control connection alive; when it closes, abort the relay
            let mut ctrl_buf = [0u8; 1];
            let _ = stream.read(&mut ctrl_buf).await;
            relay_handle.abort();
            reaper_handle.abort();
        }
        _ => {
            send_reply(&mut stream, REP_CMD_NOT_SUPPORTED, &dst).await?;
            return Err(anyhow!("unsupported SOCKS5 command: {cmd}"));
        }
    }

    Ok(())
}

/// A live SOCKS5 UDP session tracked in the NAT table.
struct SocksUdpSession {
    /// Outbound channel (trait object — works for DIRECT, SS, or any proxy).
    outbound: Arc<dyn OutboundPacketConn>,
    /// Last time a datagram was seen on this session.
    last_active: Instant,
}

/// Create a new SOCKS5 UDP session: perform rule matching via the
/// ConnectionManager, obtain an OutboundPacketConn via the handler's
/// `connect_datagram`, and send the initial datagram.
///
/// Mirrors the TUN module's `create_udp_session` but for SOCKS5 inbound.
async fn create_socks_udp_session(
    src: SocketAddr,
    dst: SocketAddr,
    initial_data: &[u8],
    target: &Address,
    conn_manager: &ConnectionManager,
) -> Result<Arc<dyn OutboundPacketConn>> {
    // Run rule engine to decide action
    let (action, domain) = conn_manager.resolve_udp_action(src, dst);

    let dns = conn_manager.dns_resolver();
    let proxies = conn_manager.proxy_manager();

    debug!(
        "SOCKS5 UDP {} -> {} ({}) => {:?}",
        src,
        target,
        domain.as_deref().unwrap_or(""),
        action
    );

    match action {
        Action::Reject | Action::RejectDrop => {
            Err(anyhow!(
                "SOCKS5 UDP packet rejected by rule engine: {src} -> {dst}"
            ))
        }

        Action::Direct => {
            let handler = proxies
                .resolve("DIRECT")
                .ok_or_else(|| anyhow!("DIRECT handler not found"))?;

            let pc: Arc<dyn OutboundPacketConn> =
                Arc::from(handler.connect_datagram(target, dns).await?);

            debug!("SOCKS5 UDP DIRECT session: {} -> {}", src, target);

            pc.send_to(initial_data, target).await?;
            Ok(pc)
        }

        Action::Proxy(ref proxy_name) => {
            // Try to route through a proxy that supports UDP
            if let Some(handler) = proxies.resolve(proxy_name) {
                match handler.connect_datagram(target, dns.clone()).await {
                    Ok(pc_box) => {
                        let pc: Arc<dyn OutboundPacketConn> = Arc::from(pc_box);

                        debug!(
                            "SOCKS5 UDP proxy '{}' session: {} -> {}",
                            proxy_name, src, target
                        );

                        pc.send_to(initial_data, target).await?;
                        return Ok(pc);
                    }
                    Err(e) => {
                        warn!(
                            "SOCKS5 UDP proxy '{}' connect_datagram failed: {}, falling back to DIRECT",
                            proxy_name, e
                        );
                    }
                }
            } else {
                warn!(
                    "SOCKS5 UDP proxy '{}' not found, falling back to DIRECT",
                    proxy_name
                );
            }

            // Fallback to DIRECT
            let direct = proxies
                .resolve("DIRECT")
                .ok_or_else(|| anyhow!("DIRECT handler not found"))?;

            let pc: Arc<dyn OutboundPacketConn> =
                Arc::from(direct.connect_datagram(target, dns).await?);

            debug!("SOCKS5 UDP DIRECT fallback session: {} -> {}", src, target);

            pc.send_to(initial_data, target).await?;
            Ok(pc)
        }
    }
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
async fn send_reply(stream: &mut TcpStream, rep: u8, bind_addr: &SocketAddr) -> Result<()> {
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
        // Create a pair of connected TCP streams for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();

        let (client_res, accept_res) = tokio::join!(connect_fut, accept_fut);
        let mut client = client_res.unwrap();
        let (mut server, _) = accept_res.unwrap();

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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();

        let (client_res, accept_res) = tokio::join!(connect_fut, accept_fut);
        let mut client = client_res.unwrap();
        let (mut server, _) = accept_res.unwrap();

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
