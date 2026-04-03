//! SOCKS5 proxy inbound listener.
//!
//! Implements RFC 1928 (SOCKS5) with no-auth and username/password (RFC 1929)
//! authentication methods. Supports CONNECT (TCP) command. UDP ASSOCIATE is
//! accepted but not yet wired through.

use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::conn::ConnectionManager;

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
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Start a SOCKS5 proxy listener on `addr`.
pub async fn run_socks_proxy(addr: SocketAddr, conn_manager: Arc<ConnectionManager>) -> Result<()> {
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
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(stream, peer, cm).await {
                debug!("SOCKS5 connection from {} ended: {}", peer, e);
            }
        });
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
) -> Result<()> {
    // --- Auth negotiation ---
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        return Err(anyhow!("unsupported SOCKS version: {}", version));
    }

    let n_methods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    // Prefer no-auth; fall back to user/pass if offered
    let chosen = if methods.contains(&AUTH_NONE) {
        AUTH_NONE
    } else if methods.contains(&AUTH_USER_PASS) {
        AUTH_USER_PASS
    } else {
        stream
            .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
            .await?;
        return Err(anyhow!("no acceptable auth method"));
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

        // Accept all credentials (auth enforcement is out of scope for now)
        stream.write_all(&[0x01, 0x00]).await?; // success
    }

    // --- Request ---
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(anyhow!("unexpected version in request: {}", ver));
    }
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved
    let atyp = stream.read_u8().await?;

    let (host, port) = read_address(&mut stream, atyp).await?;

    // Resolve to SocketAddr
    let dst = resolve_target(&host, port).await?;

    match cmd {
        CMD_CONNECT => {
            // Send success reply
            send_reply(&mut stream, REP_SUCCESS, &dst).await?;

            conn_manager
                .handle_tcp_typed(peer, dst, stream, "socks5")
                .await?;
        }
        CMD_UDP_ASSOCIATE => {
            // Bind a UDP socket and tell the client its address. The actual
            // UDP relay is not yet implemented — we just report success so
            // that clients don't error out.
            let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
            send_reply(&mut stream, REP_SUCCESS, &bind_addr).await?;

            // Keep the TCP control connection alive until the client closes it
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        }
        _ => {
            send_reply(&mut stream, REP_CMD_NOT_SUPPORTED, &dst).await?;
            return Err(anyhow!("unsupported SOCKS5 command: {}", cmd));
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
        _ => Err(anyhow!("unsupported SOCKS5 address type: {}", atyp)),
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
) -> Result<()> {
    handle_socks5(stream, peer, conn_manager).await
}

/// Resolve host:port to a SocketAddr.
async fn resolve_target(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await?
        .collect();
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("DNS resolution failed for {}", host))
}
