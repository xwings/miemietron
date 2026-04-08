pub mod device;
pub mod route;

use anyhow::Result;
use dashmap::DashMap;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::common::addr::Address;
use crate::config::TunConfig;
use crate::conn::ConnectionManager;
use crate::dns::DnsResolver;
use crate::proxy::OutboundPacketConn;
use crate::rules::Action;
use crate::stack::gvisor::GvisorStack;
use crate::stack::system::{self, SystemStack, TCP_REDIR_PORT, UDP_TPROXY_PORT};
use device::TunDevice;

/// Routing mark used to prevent loops.
/// Outbound proxy connections are marked with this so they use the main routing
/// table (bypassing the TUN) via the ip rule set up in route::setup_routes.
const FWMARK: &str = "0x162";

/// Main TUN event loop.
///
/// 1. Opens the TUN device and configures routes.
/// 2. Sets up iptables REDIRECT (TCP) and TPROXY (UDP) rules.
/// 3. Starts a SystemStack TCP listener for redirected connections.
/// 4. Accepts connections in a loop, recovers the original destination via
///    SO_ORIGINAL_DST, and hands them to ConnectionManager for proxying.
/// 5. Spawns a background task to drain packets from the TUN fd (the kernel
///    requires someone to read them; the actual TCP/UDP processing happens
///    via the redirected sockets, not by parsing raw packets).
pub async fn run_tun(
    config: TunConfig,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
    dns_listen: Option<String>,
) -> Result<()> {
    let tun_dev = TunDevice::open(&config)?;
    info!("TUN device {} opened (MTU {})", config.device, config.mtu);

    if config.auto_detect_interface {
        if let Some(iface) = route::detect_default_interface().await {
            info!("Auto-detected outbound interface: {}", iface);
            // Store for use by outbound socket binding
            // The interface is used by connect opts in transport/tcp.rs
        } else {
            tracing::warn!("auto-detect-interface enabled but could not detect default interface");
        }
    }

    // Only set up routes and firewall rules when auto-route is enabled.
    // When auto-route is false, an external manager (e.g. OpenClash) handles
    // all firewall rules and redirects traffic to redir-port/tproxy-port instead.
    if config.auto_route {
        route::setup_routes(&config).await?;
        info!("Auto-route configured");

        route::setup_iptables(&config.device, TCP_REDIR_PORT, UDP_TPROXY_PORT, FWMARK).await?;
        info!("iptables redirect rules configured");
    } else {
        info!(
            "Auto-route disabled — skipping route and firewall setup (external manager expected)"
        );
    }

    let stack_type = config.stack.to_lowercase();
    match stack_type.as_str() {
        "gvisor" | "mixed" => {
            info!(
                "TUN {} using {} stack (user-space TCP/IP)",
                config.device, stack_type
            );
            run_gvisor_stack(tun_dev, &config, conn_manager, dns, &stack_type, &dns_listen).await
        }
        _ => {
            // "system" stack (default) — kernel TCP/IP via iptables REDIRECT
            run_system_stack(tun_dev, &config, conn_manager, dns).await
        }
    }
}

/// Run the system stack: kernel TCP/IP via iptables REDIRECT + SO_ORIGINAL_DST.
async fn run_system_stack(
    tun_dev: TunDevice,
    config: &TunConfig,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
) -> Result<()> {
    // Start the system stack (TCP listener)
    let stack = SystemStack::new(&config.device, TCP_REDIR_PORT).await?;

    // Drain TUN fd in background
    let tun_mtu = config.mtu;
    tokio::spawn(async move {
        drain_tun_device(tun_dev, tun_mtu).await;
    });

    // Start UDP relay in background
    let udp_dns = dns.clone();
    let udp_conn = conn_manager.clone();
    let udp_timeout = config.udp_timeout;
    tokio::spawn(async move {
        if let Err(e) = run_udp_relay(UDP_TPROXY_PORT, udp_conn, udp_dns, udp_timeout).await {
            error!("UDP relay error: {}", e);
        }
    });

    // TCP accept loop
    info!(
        "TUN {} ready — system stack, TCP on port {}",
        config.device, TCP_REDIR_PORT
    );

    loop {
        match stack.accept_tcp().await {
            Ok((stream, src, orig_dst)) => {
                let cm = conn_manager.clone();
                let dns = dns.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_connection(stream, src, orig_dst, &cm, &dns).await {
                        debug!("TCP connection {} -> {} error: {}", src, orig_dst, e);
                    }
                });
            }
            Err(e) => {
                error!("TCP accept error: {}", e);
            }
        }
    }
}

/// Run the gvisor stack: user-space TCP/IP processing raw TUN packets.
///
/// In "gvisor" mode, both TCP and UDP are handled by the user-space stack.
/// In "mixed" mode, TCP uses the user-space stack and UDP uses the kernel
/// TPROXY path (same as system stack).
/// Parse dns-hijack entries and DNS listen address into a set of (hijack_addr → dns_addr) mappings.
fn parse_dns_hijack(
    hijack_entries: &[String],
    dns_listen: &Option<String>,
) -> Vec<(SocketAddr, SocketAddr)> {
    let dns_addr = dns_listen
        .as_deref()
        .unwrap_or("127.0.0.1:1053")
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| "127.0.0.1:1053".parse().unwrap());
    hijack_entries
        .iter()
        .filter_map(|entry| {
            entry
                .parse::<SocketAddr>()
                .ok()
                .map(|addr| (addr, dns_addr))
        })
        .collect()
}

/// Check if a destination matches any dns-hijack entry.
/// 0.0.0.0 in the hijack list matches any IP on that port.
fn dns_hijack_target(
    dst: SocketAddr,
    hijack_map: &[(SocketAddr, SocketAddr)],
) -> Option<SocketAddr> {
    for (hijack, dns_target) in hijack_map {
        if hijack.port() == dst.port() {
            let ip = hijack.ip();
            if ip.is_unspecified() || ip == dst.ip() {
                return Some(*dns_target);
            }
        }
    }
    None
}

async fn run_gvisor_stack(
    tun_dev: TunDevice,
    config: &TunConfig,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
    stack_type: &str,
    dns_listen: &Option<String>,
) -> Result<()> {
    let gvisor = GvisorStack::start(tun_dev, config);
    let (mut tcp_rx, mut udp_rx) = gvisor.into_channels();

    // Parse dns-hijack entries for UDP interception
    let hijack_map = parse_dns_hijack(&config.dns_hijack, dns_listen);
    if !hijack_map.is_empty() {
        info!("DNS hijack entries: {:?}", hijack_map);
    }

    // For "mixed" mode, also start the kernel UDP relay
    let is_mixed = stack_type == "mixed";
    if is_mixed {
        let udp_dns = dns.clone();
        let udp_conn = conn_manager.clone();
        let udp_timeout = config.udp_timeout;
        tokio::spawn(async move {
            if let Err(e) = run_udp_relay(UDP_TPROXY_PORT, udp_conn, udp_dns, udp_timeout).await {
                error!("UDP relay error (mixed mode): {}", e);
            }
        });
    }

    info!(
        "TUN {} ready — {} stack, processing raw packets",
        config.device, stack_type
    );

    // Handle TCP connections from the gvisor stack
    // UDP is handled by kernel TPROXY in mixed mode, or by gvisor in full mode
    if is_mixed {
        // Mixed mode: only process TCP from gvisor
        loop {
            match tcp_rx.recv().await {
                Some(stream) => {
                    let src = stream.src;
                    let dst = stream.dst;
                    let cm = conn_manager.clone();
                    tokio::spawn(async move {
                        if let Err(e) = cm.handle_tcp(src, dst, stream).await {
                            debug!("Gvisor TCP {} -> {} error: {}", src, dst, e);
                        }
                    });
                }
                None => {
                    error!("Gvisor TCP channel closed");
                    break;
                }
            }
        }
    } else {
        // Full gvisor mode: process both TCP and UDP
        loop {
            tokio::select! {
                tcp = tcp_rx.recv() => {
                    match tcp {
                        Some(stream) => {
                            let src = stream.src;
                            let dst = stream.dst;
                            let cm = conn_manager.clone();
                            tokio::spawn(async move {
                                if let Err(e) = cm.handle_tcp(src, dst, stream).await {
                                    debug!("Gvisor TCP {} -> {} error: {}", src, dst, e);
                                }
                            });
                        }
                        None => {
                            error!("Gvisor TCP channel closed");
                            break;
                        }
                    }
                }
                udp = udp_rx.recv() => {
                    if let Some(dgram) = udp {
                        // Check dns-hijack: redirect DNS queries to internal resolver
                        if let Some(dns_target) = dns_hijack_target(dgram.dst, &hijack_map) {
                            tokio::spawn(async move {
                                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                                    let _ = sock.send_to(&dgram.data, dns_target).await;
                                }
                            });
                        } else {
                        let cm = conn_manager.clone();
                        tokio::spawn(async move {
                            let (action, _domain) = cm.resolve_udp_action(dgram.src, dgram.dst);
                            match action {
                                Action::Direct | Action::Proxy(_) => {
                                    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                                        let _ = sock.send_to(&dgram.data, dgram.dst).await;
                                    }
                                }
                                _ => {}
                            }
                        });
                        }
                    } else {
                        error!("Gvisor UDP channel closed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a single redirected TCP connection end-to-end.
async fn handle_tcp_connection(
    stream: tokio::net::TcpStream,
    src: SocketAddr,
    orig_dst: SocketAddr,
    conn_manager: &ConnectionManager,
    _dns: &DnsResolver,
) -> Result<()> {
    // Set the routing mark on the accepted socket so any data we send back
    // doesn't get re-routed into the TUN.  (The proxy outbound connections
    // should also be marked, but that happens inside the proxy handlers.)
    set_socket_mark(&stream, 0x162);

    debug!("Handling TCP {} -> {}", src, orig_dst);

    // ConnectionManager::handle_tcp does:
    // - FakeIP reverse lookup (if dst IP is in fake-ip range)
    // - Rule matching
    // - Proxy connection
    // - Bidirectional relay
    conn_manager.handle_tcp(src, orig_dst, stream).await
}

/// Set SO_MARK on a tokio TcpStream so outgoing packets are marked for
/// routing purposes (bypass TUN).
fn set_socket_mark(stream: &tokio::net::TcpStream, mark: u32) {
    use std::os::unix::io::AsRawFd;
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
            "setsockopt SO_MARK failed: {} (non-fatal, need CAP_NET_ADMIN)",
            std::io::Error::last_os_error()
        );
    }
}

/// Read and discard packets from the TUN device.
///
/// The kernel enqueues IP packets on the TUN fd.  When we use iptables
/// REDIRECT, the kernel still delivers copies to the TUN read side.
/// If nobody reads them the internal buffer fills up and new packets are
/// dropped (which blocks the redirected TCP connections from working).
async fn drain_tun_device(mut tun: TunDevice, mtu: u32) {
    let mut buf = vec![0u8; mtu as usize + 64];
    loop {
        match tun.read(&mut buf).await {
            Ok(0) => {
                warn!("TUN device closed, stopping drain");
                break;
            }
            Ok(_n) => {
                // Packet consumed and discarded.  TCP/UDP processing happens
                // through the redirected sockets, not here.
            }
            Err(e) => {
                // EAGAIN / EWOULDBLOCK are normal; anything else is worth
                // logging once.
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    debug!("TUN read error (drain): {}", e);
                }
            }
        }
    }
}

/// A live UDP session tracked in the NAT table.
struct UdpSession {
    /// Outbound channel (trait object — works for Direct, SS, or any future protocol).
    outbound: Arc<dyn OutboundPacketConn>,
    /// Last time a datagram was seen on this session.
    last_active: Instant,
    /// The target address for the proxy (domain or IP).
    target: Address,
}

/// Receive a UDP datagram via `recvmsg`, extracting both the source address
/// and the **original destination** from `IP_RECVORIGDSTADDR` ancillary data.
///
/// This is the key syscall for TPROXY: the kernel delivers the packet with its
/// original destination still encoded in a `cmsg`.
fn recvmsg_orig_dst(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    // iovec for the payload
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Space for ancillary data (one sockaddr_in control message)
    let mut cmsg_buf = [0u8; 128];

    let mut src_storage: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = src_storage.as_mut_ptr() as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let n = n as usize;

    // Extract source address
    let src_addr = unsafe {
        let sa = src_storage.assume_init();
        if sa.ss_family == libc::AF_INET as libc::sa_family_t {
            let sin = &*(&sa as *const libc::sockaddr_storage as *const libc::sockaddr_in);
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                u16::from_be(sin.sin_port),
            ))
        } else {
            return Err(std::io::Error::other(
                "unsupported address family for UDP source",
            ));
        }
    };

    // Walk control messages to find IP_RECVORIGDSTADDR
    let mut orig_dst: Option<SocketAddr> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == libc::IP_RECVORIGDSTADDR {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let sin = &*data_ptr;
                orig_dst = Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                    u16::from_be(sin.sin_port),
                )));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let dst_addr = orig_dst
        .ok_or_else(|| std::io::Error::other("IP_RECVORIGDSTADDR not found in ancillary data"))?;

    Ok((n, src_addr, dst_addr))
}

/// Full UDP relay for TPROXY'd datagrams.
///
/// Uses `recvmsg` with `IP_RECVORIGDSTADDR` to recover the original destination.
/// For each unique (src, dst) pair, maintains a NAT mapping with idle timeout.
/// Datagrams are forwarded to the destination (DIRECT) or through the proxy.
/// Replies are sent back through the TPROXY socket to the original client.
async fn run_udp_relay(
    port: u16,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
    timeout_secs: u64,
) -> Result<()> {
    let socket = match system::create_udp_tproxy_socket(port).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "Failed to create UDP TPROXY socket: {} (UDP relay disabled)",
                e
            );
            return Ok(());
        }
    };

    let listener = Arc::new(socket);
    let nat_table: Arc<DashMap<(SocketAddr, SocketAddr), UdpSession>> = Arc::new(DashMap::new());
    let timeout_dur = Duration::from_secs(timeout_secs);

    info!(
        "UDP relay listening on port {} (timeout {}s)",
        port, timeout_secs
    );

    // Spawn a reaper task to clean up idle sessions
    let reaper_table = nat_table.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = Instant::now();
            reaper_table.retain(|_key, session: &mut UdpSession| {
                now.duration_since(session.last_active) < timeout_dur
            });
        }
    });

    let raw_fd = listener.as_raw_fd();
    let mut buf = vec![0u8; 65535];

    loop {
        // Wait for the socket to be readable
        listener.readable().await?;

        // Use recvmsg to get the original destination
        let (n, src_addr, orig_dst) = match recvmsg_orig_dst(raw_fd, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
                debug!("UDP recvmsg error: {}", e);
                continue;
            }
        };

        let data = buf[..n].to_vec();
        let key = (src_addr, orig_dst);

        // Check if we already have a session for this (src, dst) pair
        if let Some(mut session) = nat_table.get_mut(&key) {
            session.last_active = Instant::now();
            let target = session.target.clone();
            let pc = session.outbound.clone();
            tokio::spawn(async move {
                if let Err(e) = pc.send_to(&data, &target).await {
                    debug!(
                        "UDP relay send error for {} -> {}: {}",
                        src_addr, orig_dst, e
                    );
                }
            });
            continue;
        }

        // New session: create a proxy-side socket and set up the reverse path
        let nat = nat_table.clone();
        let _listener_clone = listener.clone();
        let cm = conn_manager.clone();
        let dns_ref = dns.clone();

        tokio::spawn(async move {
            match create_udp_session(src_addr, orig_dst, &data, &cm, &dns_ref).await {
                Ok(session) => {
                    let outbound = session.outbound;
                    let target = session.target;

                    let pc_rev = outbound.clone();
                    nat.insert(
                        (src_addr, orig_dst),
                        UdpSession {
                            outbound,
                            last_active: Instant::now(),
                            target: target.clone(),
                        },
                    );

                    // Spawn reverse-path relay: outbound -> client
                    let nat_rev = nat.clone();
                    tokio::spawn(async move {
                        let mut rbuf = vec![0u8; 65535];
                        loop {
                            let recv = tokio::time::timeout(
                                timeout_dur,
                                pc_rev.recv_from(&mut rbuf),
                            )
                            .await;

                            match recv {
                                Ok(Ok((rn, _))) => {
                                    if rn == 0 {
                                        break;
                                    }
                                    if let Some(mut s) =
                                        nat_rev.get_mut(&(src_addr, orig_dst))
                                    {
                                        s.last_active = Instant::now();
                                    }
                                    if let Err(e) =
                                        send_udp_from(orig_dst, src_addr, &rbuf[..rn])
                                    {
                                        debug!(
                                            "UDP reverse send {} -> {} error: {}",
                                            orig_dst, src_addr, e
                                        );
                                        break;
                                    }
                                }
                                Ok(Err(e)) => {
                                    debug!("UDP proxy recv error: {}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!(
                                        "UDP session {} -> {} timed out",
                                        src_addr, orig_dst
                                    );
                                    break;
                                }
                            }
                        }
                        nat_rev.remove(&(src_addr, orig_dst));
                    });
                }
                Err(e) => {
                    debug!(
                        "Failed to create UDP session {} -> {}: {}",
                        src_addr, orig_dst, e
                    );
                }
            }
        });
    }
}

/// Result of creating a UDP session -- contains the outbound channel and target.
struct UdpSessionResult {
    outbound: Arc<dyn OutboundPacketConn>,
    target: Address,
}

/// Create a new UDP session: perform rule matching, obtain an OutboundPacketConn
/// via the handler's `connect_datagram`, and send the initial datagram.
async fn create_udp_session(
    src: SocketAddr,
    dst: SocketAddr,
    initial_data: &[u8],
    conn_manager: &ConnectionManager,
    dns: &Arc<DnsResolver>,
) -> Result<UdpSessionResult> {
    // Run rule engine to decide action
    let (action, domain) = conn_manager.resolve_udp_action(src, dst);

    // mihomo: preHandleMetadata -- drop if FakeIP reverse lookup failed
    if domain.is_none() && dns.is_fake_ip(&dst.ip()) {
        debug!("fake DNS record {} missing", dst.ip());
        return Err(anyhow::anyhow!("fake DNS record {} missing", dst.ip()));
    }

    let target = if let Some(ref domain) = domain {
        Address::domain(domain, dst.port())
    } else {
        Address::ip(dst)
    };

    debug!(
        "UDP {} -> {} ({}) => {:?}",
        src,
        target,
        domain.as_deref().unwrap_or(""),
        action
    );

    let dns_arc = dns.clone();
    let proxies = conn_manager.proxy_manager();

    match action {
        Action::Reject | Action::RejectDrop => {
            // Drop the packet by returning an error
            Err(anyhow::anyhow!(
                "UDP packet rejected by rule engine: {src} -> {dst}"
            ))
        }

        Action::Direct => {
            let handler = proxies
                .resolve("DIRECT")
                .ok_or_else(|| anyhow::anyhow!("DIRECT handler not found"))?;

            let pc: Arc<dyn OutboundPacketConn> =
                Arc::from(handler.connect_datagram(&target, dns_arc).await?);

            debug!("UDP DIRECT session: {} -> {}", src, dst);

            pc.send_to(initial_data, &target).await?;

            Ok(UdpSessionResult {
                outbound: pc,
                target,
            })
        }

        Action::Proxy(ref proxy_name) => {
            // Try to route through a proxy that supports UDP
            if let Some(handler) = proxies.resolve(proxy_name) {
                match handler.connect_datagram(&target, dns_arc.clone()).await {
                    Ok(pc_box) => {
                        let pc: Arc<dyn OutboundPacketConn> = Arc::from(pc_box);

                        debug!(
                            "UDP proxy '{}' session: {} -> {}",
                            proxy_name, src, dst
                        );

                        pc.send_to(initial_data, &target).await?;

                        return Ok(UdpSessionResult {
                            outbound: pc,
                            target,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "UDP proxy '{}' connect_datagram failed: {}, falling back to DIRECT",
                            proxy_name, e
                        );
                    }
                }
            } else {
                warn!(
                    "UDP proxy '{}' not found, falling back to DIRECT",
                    proxy_name
                );
            }

            // Fallback to DIRECT
            let direct = proxies
                .resolve("DIRECT")
                .ok_or_else(|| anyhow::anyhow!("DIRECT handler not found"))?;

            let pc: Arc<dyn OutboundPacketConn> =
                Arc::from(direct.connect_datagram(&target, dns_arc).await?);

            debug!("UDP DIRECT fallback session: {} -> {}", src, dst);

            pc.send_to(initial_data, &target).await?;

            Ok(UdpSessionResult {
                outbound: pc,
                target,
            })
        }
    }
}

/// Send a UDP datagram that appears to originate from `from_addr` to `to_addr`.
///
/// Uses `IP_TRANSPARENT` + `bind` on the spoofed source, which is what TPROXY
/// requires for the reverse path.
fn send_udp_from(from_addr: SocketAddr, to_addr: SocketAddr, data: &[u8]) -> std::io::Result<()> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // IP_TRANSPARENT allows binding to a non-local address
    let on: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // SO_MARK to bypass TUN
    let mark: u32 = 0x162;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }

    sock.set_reuse_address(true)?;
    sock.bind(&socket2::SockAddr::from(from_addr))?;
    sock.send_to(data, &socket2::SockAddr::from(to_addr))?;

    Ok(())
}

/// Run a standalone UDP TPROXY listener on the given port.
///
/// This is used when `tproxy-port` is configured (e.g. by OpenClash) to accept
/// TPROXY'd UDP datagrams independently of the TUN device.
pub async fn run_tproxy_udp_listener(
    port: u16,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
) -> Result<()> {
    // Default UDP session timeout of 300 seconds
    run_udp_relay(port, conn_manager, dns, 300).await
}

/// Cleanup guard that removes iptables rules when the TUN module shuts down.
/// This is called from the Engine when it aborts the TUN task.
pub async fn cleanup(config: &TunConfig) -> Result<()> {
    if config.auto_route {
        route::cleanup_iptables(&config.device).await?;
        route::cleanup_routes(config).await?;
    }
    Ok(())
}
