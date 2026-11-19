pub mod device;
pub mod route;

use anyhow::Result;
use dashmap::DashMap;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::TunConfig;
use crate::conn::{
    udp::{self, UdpInbound, UdpPacket},
    ConnectionManager,
};
use crate::dns::{DnsResolver, ResolverProvider};
use crate::stack::smol::{SmolStack, SmolUdpPacket, UdpSender};
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
    dns: ResolverProvider,
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
    dns: ResolverProvider,
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
    let (mut tcp_rx, mut udp_rx, udp_out) = stack.into_channels();
    // mihomo compat: the tunnel's NAT table — one UDP session per client
    // socket, whatever it sends to.
    let udp_nat: Arc<DashMap<SocketAddr, mpsc::Sender<UdpPacket>>> = Arc::new(DashMap::new());

    // dns-hijack: destinations matching an entry are answered by the internal
    // resolver in-stack, both TCP and UDP (mihomo sing_tun/dns.go ShouldHijackDns).
    let hijack = Arc::new(parse_dns_hijack_targets(&config.dns_hijack));
    if !hijack.is_empty() {
        info!("TUN dns-hijack active for: {:?}", hijack);
    }
    let _ = dns_listen; // hijacked queries are served locally, not forwarded

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
                let Some(packet) = udp else {
                    error!("smoltcp UDP channel closed");
                    break;
                };
                if dns_hijack_matches(&hijack, packet.dst) {
                    let dns = dns.clone();
                    let out = udp_out.clone();
                    tokio::spawn(async move {
                        handle_hijacked_dns_udp(packet, &dns, &out).await;
                    });
                    continue;
                }
                let src = packet.src;
                let queued = udp::enqueue(&udp_nat, src, UdpPacket::new(packet.dst, packet.data));
                let Some((tx, rx)) = queued else {
                    continue;
                };
                let cm = conn_manager.clone();
                let nat = udp_nat.clone();
                let out = udp_out.clone();
                tokio::spawn(async move {
                    let session = cm.handle_udp(
                        UdpInbound { src, conn_type: "tun" },
                        rx,
                        |data, from| {
                            let out = out.clone();
                            async move {
                                if out.send(from, src, data).await {
                                    Ok(())
                                } else {
                                    Err(anyhow::anyhow!("TUN stack closed"))
                                }
                            }
                        },
                    );
                    if let Err(e) = session.await {
                        debug!("TUN UDP session {} error: {}", src, e);
                    }
                    nat.remove_if(&src, |_, existing| existing.same_channel(&tx));
                });
            }
        }
    }

    Ok(())
}

/// Answer a hijacked DNS-over-UDP query from the internal resolver, back
/// through the stack from the address it was sent to.
///
/// mihomo compat: `resolver.RelayDnsPacket` serves from the resolver of the
/// running config — the one a reload swapped in, asked for per query.
async fn handle_hijacked_dns_udp(packet: SmolUdpPacket, dns: &ResolverProvider, out: &UdpSender) {
    debug!("[DNS] hijack udp:{} from {}", packet.dst, packet.src);
    let reply_limit = Some(crate::dns::SAFE_DNS_PACKET_SIZE);
    if let Some(resp) = crate::dns::process_dns_query(&packet.data, &dns(), reply_limit).await {
        out.send(packet.dst, packet.src, resp).await;
    }
}

/// Answer a hijacked DNS-over-TCP connection (2-byte length-prefixed messages)
/// from the internal resolver.
async fn handle_hijacked_dns_tcp(
    mut stream: crate::stack::smol::SmolTcpStream,
    dns: &ResolverProvider,
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
        if let Some(resp) = crate::dns::process_dns_query(&msg, &dns(), None).await {
            stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
            stream.write_all(&resp).await?;
        }
    }
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

/// UDP relay for TPROXY'd datagrams.
///
/// Uses `recvmsg` with `IP_RECVORIGDSTADDR` to recover the original
/// destination. Every client socket gets one session (mihomo's NAT table);
/// replies go back through sockets bound to the address they come from.
async fn run_udp_relay(
    port: u16,
    conn_manager: Arc<ConnectionManager>,
    _dns: Arc<DnsResolver>,
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
    let nat_table: Arc<DashMap<SocketAddr, mpsc::Sender<UdpPacket>>> = Arc::new(DashMap::new());

    info!("UDP relay listening on port {}", port);

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

        let packet = UdpPacket::new(orig_dst, buf[..n].to_vec());
        let Some((tx, rx)) = udp::enqueue(&nat_table, src_addr, packet) else {
            continue;
        };
        let nat = nat_table.clone();
        let cm = conn_manager.clone();
        tokio::spawn(async move {
            let local = LocalConns::new(src_addr, tx.clone());
            let session = cm.handle_udp(
                UdpInbound {
                    src: src_addr,
                    conn_type: "tproxy",
                },
                rx,
                |data, from| {
                    let local = &local;
                    async move { local.write_back(from, &data).await }
                },
            );
            if let Err(error) = session.await {
                debug!("UDP session {} error: {}", src_addr, error);
            }
            nat.remove_if(&src_addr, |_, existing| existing.same_channel(&tx));
        });
    }
}

/// The sockets one TPROXY client is answered through, one per address it is
/// answered from.
///
/// mihomo compat: listener/tproxy/packet.go `createOrGetLocalConn` — a
/// socket is bound (transparently) to the remote address and connected to
/// the client, kept for the life of the NAT entry, and read as well: once it
/// exists the kernel hands it the client's datagrams for that remote instead
/// of the TPROXY listener.
struct LocalConns {
    client: SocketAddr,
    session: mpsc::Sender<UdpPacket>,
    conns: tokio::sync::Mutex<std::collections::HashMap<SocketAddr, LocalConn>>,
}

struct LocalConn {
    socket: Arc<tokio::net::UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for LocalConn {
    fn drop(&mut self) {
        debug!(
            "Closing TProxy local conn... rAddr={:?}",
            self.socket.local_addr().ok()
        );
        self.reader.abort();
    }
}

impl LocalConns {
    fn new(client: SocketAddr, session: mpsc::Sender<UdpPacket>) -> Self {
        Self {
            client,
            session,
            conns: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Send `data` to the client as coming from `from`.
    async fn write_back(&self, from: SocketAddr, data: &[u8]) -> Result<()> {
        let socket = {
            let mut conns = self.conns.lock().await;
            match conns.get(&from) {
                Some(conn) => conn.socket.clone(),
                None => {
                    let socket = match dial_transparent_udp(from, self.client) {
                        Ok(socket) => Arc::new(socket),
                        Err(e) => {
                            error!(
                                "listenLocalConn failed with error: {}, packet loss (rAddr={} lAddr={})",
                                e, from, self.client
                            );
                            return Err(e.into());
                        }
                    };
                    debug!(
                        "TProxy listenLocalConn rAddr={} lAddr={}",
                        from, self.client
                    );
                    let reader =
                        tokio::spawn(read_local_conn(socket.clone(), from, self.session.clone()));
                    conns.insert(
                        from,
                        LocalConn {
                            socket: socket.clone(),
                            reader,
                        },
                    );
                    socket
                }
            }
        };
        socket.send(data).await?;
        Ok(())
    }
}

/// Feed what the client sends to `remote` through a local conn into its
/// session.
async fn read_local_conn(
    socket: Arc<tokio::net::UdpSocket>,
    remote: SocketAddr,
    session: mpsc::Sender<UdpPacket>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv(&mut buf).await {
            // A full queue drops the datagram, as on the listener.
            Ok(n) => {
                let _ = session.try_send(UdpPacket::new(remote, buf[..n].to_vec()));
            }
            // An ICMP error surfacing on the connected socket is not the end
            // of it; anything else is.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(e) => {
                debug!("TProxy local conn listener exit.. rAddr={}: {}", remote, e);
                break;
            }
        }
    }
}

/// A UDP socket bound to the non-local `from` and connected to `to`.
///
/// mihomo compat: listener/tproxy/udp_linux.go `dialUDP` — SO_REUSEADDR and
/// IP_TRANSPARENT, and no SO_MARK: OpenClash routes its own mark to `lo`,
/// which a marked reply would follow instead of reaching the client.
fn dial_transparent_udp(
    from: SocketAddr,
    to: SocketAddr,
) -> std::io::Result<tokio::net::UdpSocket> {
    let (domain, level, option) = if from.is_ipv4() && to.is_ipv4() {
        (socket2::Domain::IPV4, libc::SOL_IP, libc::IP_TRANSPARENT)
    } else {
        (
            socket2::Domain::IPV6,
            libc::SOL_IPV6,
            libc::IPV6_TRANSPARENT,
        )
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            option,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    sock.bind(&socket2::SockAddr::from(from))?;
    sock.connect(&socket2::SockAddr::from(to))?;
    sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(sock.into())
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
    run_udp_relay(port, conn_manager, dns).await
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
