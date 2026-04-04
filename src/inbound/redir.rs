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
use tokio::net::{TcpListener, TcpStream};
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
    // Build the TCP listener with SO_REUSEADDR and IP_TRANSPARENT.
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .context("failed to create redir TCP socket")?;

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // IP_TRANSPARENT allows accepting connections destined for any IP
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        warn!(
            "setsockopt IP_TRANSPARENT on redir socket failed (need CAP_NET_ADMIN?): {}",
            std::io::Error::last_os_error()
        );
    }

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&socket2::SockAddr::from(bind_addr))
        .with_context(|| format!("failed to bind redir listener on port {port}"))?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener)
        .context("failed to convert redir listener to tokio TcpListener")?;

    info!("Transparent TCP (redir-port) listening on 0.0.0.0:{}", port);

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
                debug!("Redir: failed to get SO_ORIGINAL_DST for {}: {}", src, e);
                continue;
            }
        };

        // Set SO_MARK on the accepted socket so replies bypass TUN
        set_socket_mark(&stream, 0x162);

        debug!("Redir TCP {} -> {} (original)", src, orig_dst);

        let cm = conn_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = cm.handle_tcp(src, orig_dst, stream).await {
                debug!("Redir TCP {} -> {} error: {}", src, orig_dst, e);
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

/// Set SO_MARK on a TcpStream to bypass TUN routing.
fn set_socket_mark(stream: &TcpStream, mark: u32) {
    let fd = stream.as_raw_fd();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        debug!(
            "setsockopt SO_MARK on redir socket failed: {}",
            std::io::Error::last_os_error()
        );
    }
}
