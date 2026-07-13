//! Transparent (TPROXY) UDP socket helper for the standalone `tproxy-port`
//! inbound listener. The TUN datapath itself uses the userspace stack
//! (`crate::stack::smol`) and needs none of this.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use tokio::net::UdpSocket;
use tracing::{info, warn};

/// Set IP_TRANSPARENT on a socket (allows binding to non-local addresses).
/// Shared by the TPROXY UDP socket here and the TPROXY TCP listener in
/// `inbound::redir`.
pub fn set_ip_transparent(socket: &socket2::Socket) -> Result<()> {
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
