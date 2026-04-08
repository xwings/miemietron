//! System network stack — uses kernel TCP/IP via iptables REDIRECT + SO_ORIGINAL_DST.
//!
//! Instead of implementing a full userspace TCP/IP stack, we leverage the kernel:
//!
//! 1. TUN device captures all routed traffic.
//! 2. iptables REDIRECT sends TCP traffic arriving on the TUN to a local listener.
//! 3. We accept connections and use `getsockopt(SO_ORIGINAL_DST)` to recover the
//!    original destination address (before the REDIRECT).
//! 4. For UDP, iptables TPROXY directs datagrams to a transparent UDP socket.
//!
//! This is the same approach used by Clash/mihomo's "system" stack mode.

use anyhow::{Context, Result};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// Port used for the transparent TCP listener.
pub const TCP_REDIR_PORT: u16 = 18443;

/// Port used for the transparent UDP listener.
pub const UDP_TPROXY_PORT: u16 = 18444;

/// SO_ORIGINAL_DST constant (not always in libc).
const SO_ORIGINAL_DST: libc::c_int = 80;

/// System stack that accepts redirected TCP connections and TPROXY'd UDP datagrams.
pub struct SystemStack {
    tcp_listener: TcpListener,
    #[allow(dead_code)]
    tun_device: String,
}

impl SystemStack {
    /// Create a new SystemStack.
    ///
    /// `tun_device` is the name of the TUN interface (used for iptables rules).
    /// `tcp_port` is the local port for the transparent TCP listener.
    pub async fn new(tun_device: &str, tcp_port: u16) -> Result<Self> {
        // Build the TCP listener using socket2 so we can set SO_REUSEADDR and
        // IP_TRANSPARENT before binding.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .context("failed to create TCP socket")?;

        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        // IP_TRANSPARENT allows us to accept connections destined for any IP.
        // This is useful in TPROXY mode; for REDIRECT mode it's not strictly
        // required but doesn't hurt.
        set_ip_transparent(&socket)?;

        let bind_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), tcp_port);
        socket
            .bind(&socket2::SockAddr::from(bind_addr))
            .with_context(|| format!("failed to bind TCP listener on port {tcp_port}"))?;
        socket.listen(1024)?;

        let std_listener: std::net::TcpListener = socket.into();
        let tcp_listener = TcpListener::from_std(std_listener)
            .context("failed to convert to tokio TcpListener")?;

        info!(
            "SystemStack TCP listener on 0.0.0.0:{} for TUN {}",
            tcp_port, tun_device
        );

        Ok(Self {
            tcp_listener,
            tun_device: tun_device.to_string(),
        })
    }

    /// Accept the next redirected TCP connection.
    ///
    /// Returns `(stream, source_addr, original_destination_addr)`.
    pub async fn accept_tcp(&self) -> Result<(TcpStream, SocketAddr, SocketAddr)> {
        let (stream, src_addr) = self
            .tcp_listener
            .accept()
            .await
            .context("TCP accept failed")?;

        // Recover the original destination using SO_ORIGINAL_DST.
        let orig_dst = get_original_dst(stream.as_raw_fd())
            .context("failed to get original destination (SO_ORIGINAL_DST)")?;

        debug!("Accepted TCP {} -> {} (original)", src_addr, orig_dst);

        Ok((stream, src_addr, orig_dst))
    }

    /// Get the TUN device name this stack is bound to.
    #[allow(dead_code)]
    pub fn tun_device(&self) -> &str {
        &self.tun_device
    }
}

/// Retrieve the original destination address of a redirected TCP connection
/// using `getsockopt(SOL_IP, SO_ORIGINAL_DST)`.
///
/// This works after iptables REDIRECT or DNAT rewrites the destination.
fn get_original_dst(fd: std::os::unix::io::RawFd) -> std::io::Result<SocketAddr> {
    // Try IPv4 first (SO_ORIGINAL_DST on SOL_IP)
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

    // If IPv4 failed, try IPv6 (IP6T_SO_ORIGINAL_DST = 80 on SOL_IPV6)
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

/// Set IP_TRANSPARENT on a socket (allows binding to non-local addresses).
fn set_ip_transparent(socket: &socket2::Socket) -> Result<()> {
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
        let err = std::io::Error::last_os_error();
        // IP_TRANSPARENT requires CAP_NET_ADMIN; warn but don't fail hard
        // since REDIRECT mode works without it.
        warn!(
            "setsockopt IP_TRANSPARENT failed (need CAP_NET_ADMIN?): {}",
            err
        );
    }
    Ok(())
}

/// Create a transparent UDP socket bound on the given port.
///
/// Uses IP_TRANSPARENT + IP_RECVORIGDSTADDR so we can recover the original
/// destination of TPROXY'd UDP packets.
pub async fn create_udp_tproxy_socket(port: u16) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("failed to create UDP socket")?;

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    set_ip_transparent(&socket)?;

    // IP_RECVORIGDSTADDR lets us read the original destination from ancillary data.
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVORIGDSTADDR,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let bind_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port);
    socket
        .bind(&socket2::SockAddr::from(bind_addr))
        .with_context(|| format!("failed to bind UDP tproxy socket on port {port}"))?;

    let std_socket: std::net::UdpSocket = socket.into();
    let udp = UdpSocket::from_std(std_socket).context("failed to convert to tokio UdpSocket")?;

    info!("SystemStack UDP TPROXY listener on 0.0.0.0:{}", port);
    Ok(udp)
}
