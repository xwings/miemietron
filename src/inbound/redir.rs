//! Transparent proxy (redir-port) listener.
//!
//! Listens on the configured redir-port for TCP connections that have been
//! redirected via iptables REDIRECT / nftables redirect. Uses
//! `getsockopt(SO_ORIGINAL_DST)` to recover the original destination,
//! then hands the connection to the ConnectionManager for rule-matching
//! and proxying.
//!
//! This is the mechanism OpenClash uses to funnel FakeIP TCP traffic into
//! the proxy core.

use anyhow::{Context, Result};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::conn::ConnectionManager;

/// SO_ORIGINAL_DST constant (not always in libc).
const SO_ORIGINAL_DST: libc::c_int = 80;

/// Run a transparent TCP proxy listener on the given port.
///
/// For each accepted connection:
/// 1. Recover the original destination via `getsockopt(SO_ORIGINAL_DST)`
/// 2. Hand the connection to `ConnectionManager::handle_tcp`
pub async fn run_redir_listener(port: u16, conn_manager: Arc<ConnectionManager>) -> Result<()> {
    // mihomo compat: simple TCP listener, no IP_TRANSPARENT (that's for TPROXY).
    // iptables REDIRECT changes the destination to localhost:port, so a regular
    // TCP listener is sufficient. SO_ORIGINAL_DST recovers the original destination.
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind redir listener on {addr}"))?;

    info!("Transparent TCP (redir-port) listening on {}", addr);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Redir accept error: {}", e);
                continue;
            }
        };

        let orig_dst = match get_original_dst(stream.as_raw_fd()) {
            Ok(dst) => dst,
            Err(e) => {
                warn!("Redir: failed to get SO_ORIGINAL_DST for {}: {}", src, e);
                continue;
            }
        };

        // mihomo compat: no SO_MARK on accepted inbound sockets.
        // mihomo's redir only calls keepalive.TCPKeepAlive(conn).
        // GID 65534 handles firewall bypass for outbound.

        debug!("Redir TCP {} -> {} (original)", src, orig_dst);

        let cm = conn_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = cm.handle_tcp(src, orig_dst, stream).await {
                debug!("Redir TCP {} -> {} error: {}", src, orig_dst, e);
            }
        });
    }
}

/// Run a transparent TCP proxy listener using TPROXY on the given port.
///
/// Unlike REDIRECT (redir-port), TPROXY preserves the original destination
/// on the socket itself. The kernel delivers packets to the listening socket
/// with the original destination intact, so `stream.local_addr()` returns
/// the original destination. The socket must be bound with `IP_TRANSPARENT`.
///
/// For each accepted connection:
/// 1. Read the original destination from `stream.local_addr()`
/// 2. Set `SO_MARK` on the accepted socket for routing bypass
/// 3. Hand the connection to `ConnectionManager::handle_tcp`
pub async fn run_tproxy_tcp_listener(
    port: u16,
    conn_manager: Arc<ConnectionManager>,
) -> Result<()> {
    // Create a raw socket so we can set IP_TRANSPARENT before bind
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;

    // Set IP_TRANSPARENT so the kernel delivers TPROXY-redirected packets to us
    unsafe {
        let on: libc::c_int = 1;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            warn!(
                "setsockopt IP_TRANSPARENT failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    socket.bind(&socket2::SockAddr::from(SocketAddr::from((
        [0, 0, 0, 0],
        port,
    ))))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;

    let listener = TcpListener::from_std(socket.into())?;
    info!("Transparent TCP (TPROXY) listening on 0.0.0.0:{}", port);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("TPROXY TCP accept error: {}", e);
                continue;
            }
        };

        // For TPROXY, local_addr() IS the original destination
        let orig_dst = match stream.local_addr() {
            Ok(dst) => dst,
            Err(e) => {
                warn!(
                    "TPROXY TCP: failed to get local_addr for {}: {}",
                    src, e
                );
                continue;
            }
        };

        // mihomo compat: no SO_MARK on accepted inbound sockets.

        debug!("TPROXY TCP {} -> {} (original)", src, orig_dst);

        let cm = conn_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = cm.handle_tcp(src, orig_dst, stream).await {
                debug!("TPROXY TCP {} -> {} error: {}", src, orig_dst, e);
            }
        });
    }
}

/// Retrieve the original destination address of a redirected TCP connection
/// using `getsockopt(SOL_IP, SO_ORIGINAL_DST)`.
fn get_original_dst(fd: std::os::unix::io::RawFd) -> std::io::Result<SocketAddr> {
    let mut addr: MaybeUninit<libc::sockaddr_in> = MaybeUninit::zeroed();
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            addr.as_mut_ptr() as *mut libc::c_void,
            &mut addr_len,
        )
    };

    if ret == 0 {
        let addr = unsafe { addr.assume_init() };
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }

    // Try IPv6 (IP6T_SO_ORIGINAL_DST = 80 on SOL_IPV6)
    let mut addr6: MaybeUninit<libc::sockaddr_in6> = MaybeUninit::zeroed();
    let mut addr6_len: libc::socklen_t =
        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            SO_ORIGINAL_DST,
            addr6.as_mut_ptr() as *mut libc::c_void,
            &mut addr6_len,
        )
    };

    if ret == 0 {
        let addr6 = unsafe { addr6.assume_init() };
        let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
        let port = u16::from_be(addr6.sin6_port);
        return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
            ip,
            port,
            addr6.sin6_flowinfo,
            addr6.sin6_scope_id,
        )));
    }

    Err(std::io::Error::last_os_error())
}
