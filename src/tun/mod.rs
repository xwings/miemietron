pub mod device;
pub mod route;

use anyhow::Result;
use dashmap::DashMap;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::TunConfig;
use crate::conn::{
    udp::{self, UdpInbound},
    ConnectionManager,
};
use crate::dns::DnsResolver;
use crate::stack::smol::SmolStack;
use crate::stack::system;
use device::TunDevice;

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

    // mihomo compat: with a userspace stack + auto-route, the proxy's own
    // outbound sockets must bypass the TUN. mihomo binds them to the physical
    // default interface (dialer.DefaultInterfaceFinder), not a firewall mark.
    // mihomo compat: dialer.go:89-95 — an explicit `interface-name` outranks the
    // finder, so the detected value goes in its own slot rather than overwriting
    // the configured one.
    if config.auto_detect_interface {
        if let Some(iface) = route::detect_default_interface().await {
            info!("Auto-detected outbound interface: {}", iface);
            crate::transport::tcp::set_detected_outbound_interface(Some(iface));
        } else {
            tracing::warn!("auto-detect-interface enabled but could not detect default interface");
        }
    }

    // Only set up routes when auto-route is enabled. When auto-route is false,
    // an external manager (e.g. OpenClash) directs traffic into the TUN.
    //
    // mihomo compat: the userspace stack terminates packets read directly from
    // the TUN device — it needs NO iptables REDIRECT (sing-tun installs none).
    // Loop avoidance is handled by binding outbound sockets to the physical
    // interface (auto-detect-interface), set above.
    if config.auto_route {
        route::setup_routes(&config).await?;
        info!("Auto-route configured");
    } else {
        info!("Auto-route disabled — skipping route setup (external manager expected)");
    }

    // mihomo compat: both "gvisor" and "system" stacks terminate TCP/UDP in
    // userspace (sing-tun's gVisor and system netstacks). We implement both via
    // the smoltcp engine; there is no kernel-iptables TUN datapath.
    let stack_type = config.stack.to_lowercase();
    info!(
        "TUN {} using {} stack (smoltcp userspace TCP/IP)",
        config.device, stack_type
    );
    run_gvisor_stack(
        tun_dev,
        &config,
        conn_manager,
        dns,
        &stack_type,
        &dns_listen,
    )
    .await
}

/// Run the gvisor stack: user-space TCP/IP processing raw TUN packets.
///
/// In "gvisor" mode, both TCP and UDP are handled by the user-space stack.
/// In "mixed" mode, TCP uses the user-space stack and UDP uses the kernel
/// TPROXY path (same as system stack).
/// Parse dns-hijack entries into socket addresses.
///
/// mihomo compat (sing_tun/server.go:273-284): each entry may carry a
/// `udp://` / `tcp://` scheme (stripped) and the literal `any` (replaced with
/// `0.0.0.0`). Unparseable entries are skipped.
fn parse_dns_hijack_targets(entries: &[String]) -> Vec<SocketAddr> {
    entries
        .iter()
        .filter_map(|entry| {
            let e = entry.rsplit("://").next().unwrap_or(entry);
            let e = e.replacen("any", "0.0.0.0", 1);
            e.parse::<SocketAddr>().ok()
        })
        .collect()
}

/// Whether a destination should have its DNS hijacked to the internal resolver.
///
/// mihomo compat (sing_tun/dns.go ShouldHijackDns): match if the destination
/// equals a hijack entry, or the entry's address is unspecified and the
/// destination port is 53.
fn dns_hijack_matches(hijack: &[SocketAddr], dst: SocketAddr) -> bool {
    hijack
        .iter()
        .any(|h| *h == dst || (h.ip().is_unspecified() && dst.port() == 53))
}

async fn run_gvisor_stack(
    tun_dev: TunDevice,
    config: &TunConfig,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
    stack_type: &str,
    dns_listen: &Option<String>,
) -> Result<()> {
    // mihomo compat: the "gvisor" stack terminates TCP/UDP in userspace via a
    // real netstack (sing-tun's gVisor stack). We use smoltcp, driven by the
    // SmolStack engine. "mixed" also terminates in userspace here (mihomo's
    // mixed = system-TCP + gvisor-UDP is not reproduced; both go through the
    // userspace stack, which is behaviorally equivalent for the proxy tunnel).
    let _ = stack_type;
    let stack = SmolStack::start(tun_dev, config.mtu as usize);
    let (mut tcp_rx, mut udp_rx) = stack.into_channels();

    // dns-hijack: destinations matching an entry are answered by the internal
    // resolver in-stack, both TCP and UDP (mihomo sing_tun/dns.go ShouldHijackDns).
    let hijack = Arc::new(parse_dns_hijack_targets(&config.dns_hijack));
    if !hijack.is_empty() {
        info!("TUN dns-hijack active for: {:?}", hijack);
    }
    let _ = dns_listen; // hijacked queries are served locally, not forwarded

    let udp_timeout = Duration::from_secs(config.udp_timeout);

    info!("TUN {} ready — smoltcp userspace stack", config.device);

    loop {
        tokio::select! {
            tcp = tcp_rx.recv() => {
                let Some(stream) = tcp else {
                    error!("smoltcp TCP channel closed");
                    break;
                };
                let src = stream.src;
                let dst = stream.dst;
                let cm = conn_manager.clone();
                let dns = dns.clone();
                let hijack = hijack.clone();
                tokio::spawn(async move {
                    if dns_hijack_matches(&hijack, dst) {
                        if let Err(e) = handle_hijacked_dns_tcp(stream, &dns).await {
                            debug!("DNS hijack tcp:{} error: {}", dst, e);
                        }
                        return;
                    }
                    if let Err(e) = cm.handle_tcp(src, dst, stream).await {
                        debug!("TUN TCP {} -> {} error: {}", src, dst, e);
                    }
                });
            }
            udp = udp_rx.recv() => {
                let Some(flow) = udp else {
                    error!("smoltcp UDP channel closed");
                    break;
                };
                let cm = conn_manager.clone();
                let dns = dns.clone();
                let hijack = hijack.clone();
                tokio::spawn(async move {
                    if dns_hijack_matches(&hijack, flow.dst) {
                        handle_hijacked_dns_udp(flow, &dns).await;
                        return;
                    }
                    if let Err(e) = handle_tun_udp_flow(flow, &cm, &dns, udp_timeout).await {
                        debug!("TUN UDP flow error: {}", e);
                    }
                });
            }
        }
    }

    Ok(())
}

/// Answer a hijacked DNS-over-UDP flow entirely from the internal resolver,
/// relaying each query's response back through the stack to the client.
async fn handle_hijacked_dns_udp(
    mut flow: crate::stack::smol::SmolUdpFlow,
    dns: &Arc<DnsResolver>,
) {
    debug!("[DNS] hijack udp:{} from {}", flow.dst, flow.src);
    // The first datagram is already queued in flow.rx.
    while let Some(query) = flow.rx.recv().await {
        if let Some(resp) = crate::dns::process_dns_query(&query, dns).await {
            if !flow.reply.send(resp).await {
                break;
            }
        }
    }
}

/// Answer a hijacked DNS-over-TCP connection (2-byte length-prefixed messages)
/// from the internal resolver.
async fn handle_hijacked_dns_tcp(
    mut stream: crate::stack::smol::SmolTcpStream,
    dns: &Arc<DnsResolver>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    debug!("[DNS] hijack tcp:{}", stream.dst);
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            return Ok(());
        }
        let mut msg = vec![0u8; msg_len];
        stream.read_exact(&mut msg).await?;
        if let Some(resp) = crate::dns::process_dns_query(&msg, dns).await {
            stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
            stream.write_all(&resp).await?;
        }
    }
}

/// Relay one smoltcp UDP flow through the proxy tunnel: rule-match once, dial
/// the outbound (DIRECT or proxy) via the handler's `connect_datagram`, forward
/// every client datagram, and pump replies back through `flow.reply`. This is
/// the userspace-stack equivalent of the TPROXY UDP relay — proxied UDP is
/// actually proxied (not leaked DIRECT) and replies reach the client.
async fn handle_tun_udp_flow(
    flow: crate::stack::smol::SmolUdpFlow,
    conn_manager: &ConnectionManager,
    _dns: &Arc<DnsResolver>,
    udp_timeout: Duration,
) -> Result<()> {
    let src = flow.src;
    let dst = flow.dst;

    conn_manager
        .handle_udp(
            UdpInbound {
                src,
                dst,
                conn_type: "tun",
                domain: None,
            },
            flow.rx,
            udp_timeout,
            |packet| {
                let reply = flow.reply.clone();
                async move {
                    if reply.send(packet).await {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("TUN UDP client flow closed"))
                    }
                }
            },
        )
        .await
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
    _dns: Arc<DnsResolver>,
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
    let nat_table: Arc<DashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>> =
        Arc::new(DashMap::new());
    let timeout_dur = Duration::from_secs(timeout_secs);

    info!(
        "UDP relay listening on port {} (timeout {}s)",
        port, timeout_secs
    );

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

        let Some((tx, rx)) = udp::enqueue(&nat_table, key, data) else {
            continue;
        };
        let nat = nat_table.clone();
        let cm = conn_manager.clone();
        tokio::spawn(async move {
            let result = cm.handle_udp(
                UdpInbound { src: src_addr, dst: orig_dst, conn_type: "tproxy", domain: None },
                rx,
                timeout_dur,
                |data| async move { send_udp_from(orig_dst, src_addr, &data).map_err(Into::into) },
            ).await;
            if let Err(error) = result {
                debug!("UDP session {} -> {} error: {}", src_addr, orig_dst, error);
            }
            nat.remove_if(&key, |_, existing| existing.same_channel(&tx));
        });
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

/// Cleanup guard that removes the TUN routes when the module shuts down.
/// This is called from the Engine when it aborts the TUN task. The userspace
/// stack installs no iptables rules, so only routes need tearing down.
pub async fn cleanup(config: &TunConfig) -> Result<()> {
    if config.auto_route {
        route::cleanup_routes(config).await?;
    }
    Ok(())
}
