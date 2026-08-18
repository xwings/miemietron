use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;

/// mihomo compat: `dialer.DefaultInterface` — the explicit top-level
/// `interface-name` from the config, applied at config load and on every
/// reload (`hub/executor/executor.go:412`).
static CONFIG_OUTBOUND_INTERFACE: RwLock<Option<String>> = RwLock::new(None);

/// mihomo compat: `dialer.DefaultInterfaceFinder` — the physical default
/// interface discovered by TUN `auto-detect-interface`. Outbound sockets bind
/// to it so the proxy's own traffic bypasses the TUN; this is how mihomo avoids
/// routing loops, NOT via a firewall mark on our sockets.
///
/// Kept in a slot separate from the configured interface so a config reload
/// that omits `interface-name` doesn't wipe the auto-detected value.
static DETECTED_OUTBOUND_INTERFACE: RwLock<Option<String>> = RwLock::new(None);

/// Set (or clear) the configured global outbound interface (`interface-name`).
pub fn set_default_outbound_interface(iface: Option<String>) {
    if let Ok(mut guard) = CONFIG_OUTBOUND_INTERFACE.write() {
        *guard = iface;
    }
}

/// Set (or clear) the auto-detected default interface (TUN loop avoidance).
pub fn set_detected_outbound_interface(iface: Option<String>) {
    if let Ok(mut guard) = DETECTED_OUTBOUND_INTERFACE.write() {
        *guard = iface;
    }
}

/// mihomo compat: `dialer.go:89-95` — a dial's own `interface-name` wins, then
/// the configured `DefaultInterface`, then the auto-detect finder.
fn default_outbound_interface() -> Option<String> {
    let configured = CONFIG_OUTBOUND_INTERFACE.read().ok().and_then(|g| g.clone());
    configured.or_else(|| DETECTED_OUTBOUND_INTERFACE.read().ok().and_then(|g| g.clone()))
}

/// Public accessor for the global default outbound interface (used by the
/// DIRECT UDP path to bind its socket for loop avoidance).
pub fn default_outbound_interface_public() -> Option<String> {
    default_outbound_interface()
}

/// Create an unconnected UDP socket bound to the global default outbound
/// interface (when one is set).
///
/// mihomo compat: the DNS client dials through `component/dialer`
/// (`dns/client.go:38,68`), so upstream DNS sockets pick up `DefaultInterface`
/// exactly like any other outbound (`dialer.go:183-189` ListenPacket). A bare
/// `UdpSocket::bind("0.0.0.0:0")` egresses on the kernel default route instead,
/// which is wrong whenever `interface-name` names something that is not the
/// default route (e.g. an LTE `wwan0` on a multi-wan router).
pub fn bind_udp_default_interface() -> Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    #[cfg(target_os = "linux")]
    {
        if let Some(iface) = default_outbound_interface() {
            socket.bind_device(Some(iface.as_bytes()))?;
        }
    }

    socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
    socket.set_nonblocking(true)?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

/// Connect options for outbound TCP connections.
#[derive(Default)]
pub struct ConnectOpts {
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub tfo: bool,
    /// mihomo compat: keepalive settings from config.
    pub keep_alive_idle: Duration,
    pub keep_alive_interval: Duration,
    pub disable_keep_alive: bool,
}

impl ConnectOpts {
    /// Build ConnectOpts from a proxy config's common fields.
    pub fn from_proxy_config(config: &crate::config::proxy::ProxyConfig) -> Self {
        Self {
            routing_mark: config.routing_mark,
            interface: config.interface_name.clone(),
            tfo: config.tfo.unwrap_or(false),
            keep_alive_idle: Duration::from_secs(config.keep_alive_idle.unwrap_or(0)),
            keep_alive_interval: Duration::from_secs(config.keep_alive_interval.unwrap_or(0)),
            disable_keep_alive: config.disable_keep_alive.unwrap_or(false),
        }
    }
}

/// Create a TCP connection with the given options.
pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // Set SO_MARK for TUN loop prevention
    if let Some(mark) = opts.routing_mark {
        #[cfg(target_os = "linux")]
        {
            socket.set_mark(mark)?;
        }
    }

    // Bind to a specific interface: the proxy's own setting wins, otherwise
    // fall back to the global auto-detected default interface (loop avoidance).
    #[cfg(target_os = "linux")]
    {
        let iface = opts.interface.clone().or_else(default_outbound_interface);
        if let Some(iface) = iface {
            socket.bind_device(Some(iface.as_bytes()))?;
        }
    }

    // Set TCP Fast Open
    if opts.tfo {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            // TCP_FASTOPEN_CONNECT = 30
            let fd = socket.as_raw_fd();
            let val: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    30, // TCP_FASTOPEN_CONNECT
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }

    // mihomo compat: TCP keepalive (keepalive.SetNetDialer in dialer.go)
    if opts.disable_keep_alive {
        socket.set_keepalive(false)?;
    } else {
        socket.set_keepalive(true)?;
        if opts.keep_alive_idle.as_secs() > 0 {
            socket.set_tcp_keepalive(
                &socket2::TcpKeepalive::new()
                    .with_time(opts.keep_alive_idle)
                    .with_interval(opts.keep_alive_interval),
            )?;
        }
    }

    socket.set_nonblocking(true)?;

    let addr2: socket2::SockAddr = addr.into();
    match socket.connect(&addr2) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e.into()),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;

    // Wait for connection to complete
    stream.writable().await?;

    // Check for connection error
    if let Some(err) = stream.take_error()? {
        return Err(err.into());
    }

    Ok(stream)
}

/// mihomo compat: inbound listeners enable TCP keepalive on accepted sockets
/// (keepalive.TCPKeepAlive — redir/tproxy call it directly, proxy listeners
/// inherit it via inbound.Listen's ListenConfig). Without it, half-dead client
/// connections linger in /connections forever. Honors `disable-keep-alive`.
pub fn apply_inbound_keepalive(stream: &tokio::net::TcpStream) {
    if INBOUND_KEEPALIVE_DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_keepalive(true);
}

static INBOUND_KEEPALIVE_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set at boot from the config's `disable-keep-alive`.
pub fn set_inbound_keepalive_disabled(disabled: bool) {
    INBOUND_KEEPALIVE_DISABLED.store(disabled, std::sync::atomic::Ordering::Relaxed);
}
