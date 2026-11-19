//! Userspace TCP/IP stack engine ("gvisor" mode) built on smoltcp.
//!
//! This is the Rust equivalent of sing-tun's gVisor netstack: it terminates
//! TCP/UDP arriving on a TUN device in userspace and exposes the flows to a
//! caller which wires them into the proxy tunnel. This module knows NOTHING
//! about proxies, DNS, rules, or ConnectionManager.
//!
//! Architecture
//! ------------
//! One dedicated `std::thread` owns everything smoltcp (all of it is !Send):
//! an in-memory packet-queue phy device, the `Interface`, the `SocketSet`,
//! and per-flow bookkeeping. The thread runs a `poll(2)` loop over:
//!
//!   * the TUN fd (POLLIN always; POLLOUT while a packet write hit EWOULDBLOCK)
//!   * an eventfd used by `SmolTcpStream` / `UdpSender` to wake the loop
//!     when the application side queued bytes to send
//!
//! with a timeout derived from `Interface::poll_delay` (capped at 1s).
//!
//! Each iteration: drain readable TUN packets into the phy rx queue (scanning
//! each packet first — a TCP SYN to an unknown 4-tuple creates a listening
//! `tcp::Socket` bound to the destination, a UDP packet to an unknown
//! destination creates a bound `udp::Socket`); run `iface.poll`; service
//! sockets (move socket data <-> app channels, emit newly-established
//! streams/flows, reap dead sockets); run `iface.poll` again to egress data
//! the service pass queued; flush the phy tx queue to the TUN fd.
//!
//! "Accept any destination" works via `Interface::set_any_ip(true)` plus a
//! default route whose gateway is one of the interface's own addresses (that
//! is the condition smoltcp 0.12 checks under any-IP), for both IPv4 and
//! IPv6. Listening TCP sockets are bound to the concrete destination
//! endpoint observed in the SYN, and UDP sockets to the destination of the
//! first datagram, so replies carry the correct source address.
//!
//! ICMP is not handled here; packets that are neither TCP nor UDP are left
//! to smoltcp's default processing (which answers ICMP echo under any-IP)
//! and no flow is surfaced. TODO(icmp): expose echo packets to the caller
//! if mihomo-parity ping behavior through gvisor is required.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket,
    UdpPacket,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{debug, info, trace, warn};

use crate::tun::device::TunDevice;

/// smoltcp TCP socket buffer sizes (per direction).
const TCP_RX_BUF: usize = 64 * 1024;
const TCP_TX_BUF: usize = 64 * 1024;
/// smoltcp UDP socket buffer sizing.
const UDP_META_ENTRIES: usize = 64;
const UDP_PAYLOAD_BUF: usize = 64 * 1024;
/// Capacity of the per-connection app<->stack mpsc channels.
const CHAN_CAP: usize = 64;
/// Capacity of the UDP datagram channels between the stack and the app, one
/// per direction and shared by every client.
const UDP_CHAN_CAP: usize = 1024;
/// How long a UDP socket outlives the last datagram through it. Each one
/// holds two `UDP_PAYLOAD_BUF` buffers, so they are not kept for long.
const UDP_SOCKET_IDLE: SmolDuration = SmolDuration::from_secs(10);
/// Abort a TCP socket when the peer stops responding for this long while we
/// have unacknowledged data outstanding (also reaps half-open handshakes).
/// Idle established connections are NOT affected: smoltcp only checks the
/// timeout while it has something to transmit.
const TCP_TIMEOUT_SECS: u64 = 60;
/// Cap on the phy tx queue; smoltcp sees "device busy" beyond this and holds
/// data in socket buffers (proper backpressure) instead of growing memory.
const MAX_TX_QUEUE: usize = 4096;
/// Backstop poll(2) timeout when smoltcp reports no pending timer.
const MAX_POLL_MS: i64 = 1000;

// ---------------------------------------------------------------------------
// Phy device: in-memory rx/tx packet queues, Medium::Ip
// ---------------------------------------------------------------------------

struct PhyDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct PhyRxToken(Vec<u8>);

impl RxToken for PhyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct PhyTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for PhyTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

impl Device for PhyDevice {
    type RxToken<'a> = PhyRxToken;
    type TxToken<'a> = PhyTxToken<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((PhyRxToken(pkt), PhyTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= MAX_TX_QUEUE {
            None
        } else {
            Some(PhyTxToken(&mut self.tx))
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// ---------------------------------------------------------------------------
// Loop waker (eventfd)
// ---------------------------------------------------------------------------

/// Wakes the poll-loop thread from async context. Backed by an eventfd.
pub struct LoopWaker {
    fd: RawFd,
}

impl LoopWaker {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn wake(&self) {
        let one: u64 = 1;
        let ret = unsafe {
            libc::write(
                self.fd,
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        // EAGAIN means the counter is already non-zero: the loop will wake.
        let _ = ret;
    }

    fn drain(&self) {
        let mut buf: u64 = 0;
        unsafe {
            libc::read(
                self.fd,
                &mut buf as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }
}

impl Drop for LoopWaker {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// Safety: LoopWaker only wraps an fd; write(2)/read(2) on an eventfd are
// thread-safe.
unsafe impl Send for LoopWaker {}
unsafe impl Sync for LoopWaker {}

// ---------------------------------------------------------------------------
// Public flow objects
// ---------------------------------------------------------------------------

/// Message from the app side of a TCP stream into the poll loop.
#[derive(Debug)]
enum AppMsg {
    Data(Vec<u8>),
    /// Half-close: flush pending data then `socket.close()` (send FIN).
    Shutdown,
}

/// A TCP connection accepted by the smoltcp stack.
///
/// `AsyncRead` yields bytes the client sent; `AsyncWrite` queues bytes that
/// the poll loop pumps into `tcp::Socket::send`, i.e. real TCP data segments
/// back to the client. `poll_shutdown` half-closes (FIN after flush).
/// Dropping the stream closes the connection gracefully once pending data is
/// flushed.
pub struct SmolTcpStream {
    /// Client source address.
    pub src: SocketAddr,
    /// Original destination address.
    pub dst: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    tx: PollSender<AppMsg>,
    waker: Arc<LoopWaker>,
    read_buf: Vec<u8>,
    read_pos: usize,
    shutdown_sent: bool,
}

impl AsyncRead for SmolTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain buffered leftovers first.
        if self.read_pos < self.read_buf.len() {
            let to_copy = (self.read_buf.len() - self.read_pos).min(buf.remaining());
            let pos = self.read_pos;
            buf.put_slice(&self.read_buf[pos..pos + to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf = data;
                    self.read_pos = to_copy;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SmolTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let len = buf.len();
                if self.tx.send_item(AppMsg::Data(buf.to_vec())).is_err() {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                self.waker.wake();
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // Data is flushed by the poll loop; nothing to do here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let _ = self.tx.send_item(AppMsg::Shutdown);
                self.shutdown_sent = true;
                self.waker.wake();
                Poll::Ready(Ok(()))
            }
            // Channel gone: the connection is already dead; shutdown is moot.
            Poll::Ready(Err(_)) => {
                self.shutdown_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SmolTcpStream {
    fn drop(&mut self) {
        // Wake the loop so it promptly notices the closed channels and
        // closes/reaps the smoltcp socket.
        self.waker.wake();
    }
}

/// A UDP datagram a client sent into the TUN.
#[derive(Debug)]
pub struct SmolUdpPacket {
    /// Client source address.
    pub src: SocketAddr,
    /// The address the client sent it to.
    pub dst: SocketAddr,
    pub data: Vec<u8>,
}

struct UdpOut {
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

/// Sends UDP datagrams to clients through the stack, from any source address:
/// a reply does not have to come from an address the client ever wrote to.
#[derive(Clone)]
pub struct UdpSender {
    tx: mpsc::Sender<UdpOut>,
    waker: Arc<LoopWaker>,
}

impl UdpSender {
    /// Queue a datagram without waiting. Returns false if the stack is gone
    /// or the queue is full (datagram dropped — UDP semantics).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn try_send(&self, from: SocketAddr, to: SocketAddr, data: Vec<u8>) -> bool {
        match self.tx.try_send(UdpOut { from, to, data }) {
            Ok(()) => {
                self.waker.wake();
                true
            }
            Err(_) => false,
        }
    }

    /// Queue a datagram, waiting for channel capacity.
    /// Returns false if the stack is gone.
    pub async fn send(&self, from: SocketAddr, to: SocketAddr, data: Vec<u8>) -> bool {
        if self.tx.send(UdpOut { from, to, data }).await.is_ok() {
            self.waker.wake();
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// SmolStack: public entry point
// ---------------------------------------------------------------------------

/// Handle to the running stack: accepted TCP connections, received UDP
/// datagrams, and the way to send UDP back. Dropping the receivers does not
/// stop the poll thread; it exits when the TUN device is closed.
pub struct SmolStack {
    tcp_rx: mpsc::Receiver<SmolTcpStream>,
    udp_rx: mpsc::Receiver<SmolUdpPacket>,
    udp_out: UdpSender,
}

impl SmolStack {
    /// Start the stack on the given TUN device. Spawns the dedicated poll
    /// thread; the `TunDevice` is moved into it (its raw fd is used with
    /// poll(2) directly — the fd is already O_NONBLOCK).
    pub fn start(tun: TunDevice, mtu: usize) -> Self {
        let (tcp_tx, tcp_rx) = mpsc::channel(256);
        let (udp_tx, udp_rx) = mpsc::channel(UDP_CHAN_CAP);
        let (out_tx, out_rx) = mpsc::channel(UDP_CHAN_CAP);
        let waker = Arc::new(LoopWaker::new().expect("eventfd creation failed"));

        let loop_waker = waker.clone();
        std::thread::Builder::new()
            .name("smol-stack".into())
            .spawn(move || {
                let core = StackCore::new(mtu, tcp_tx, udp_tx, out_rx, loop_waker.clone());
                run_loop(tun, core, loop_waker);
            })
            .expect("failed to spawn smol-stack thread");

        Self {
            tcp_rx,
            udp_rx,
            udp_out: UdpSender { tx: out_tx, waker },
        }
    }

    /// Decompose into the TCP and UDP channels for use with tokio::select!,
    /// plus the sender for UDP towards clients.
    pub fn into_channels(
        self,
    ) -> (
        mpsc::Receiver<SmolTcpStream>,
        mpsc::Receiver<SmolUdpPacket>,
        UdpSender,
    ) {
        (self.tcp_rx, self.udp_rx, self.udp_out)
    }
}

// ---------------------------------------------------------------------------
// Stack core (owned by the poll thread; also driven directly by tests)
// ---------------------------------------------------------------------------

struct TcpConnIo {
    /// socket -> app. Dropped (None) to signal EOF once the peer half-closed
    /// and the receive buffer is drained, or when the app receiver is gone.
    to_app: Option<mpsc::Sender<Vec<u8>>>,
    /// app -> socket. THE critical direction the old gvisor.rs dropped on
    /// the floor: this receiver is owned by the poll loop and its bytes are
    /// written into `tcp::Socket::send`, becoming real TCP data segments.
    from_app: mpsc::Receiver<AppMsg>,
    /// Partially-sent outbound chunk (socket send buffer was full).
    pending: Vec<u8>,
    pending_pos: usize,
    /// App half-closed (Shutdown) or went away (channel disconnected).
    write_done: bool,
    /// `socket.close()` already called.
    close_called: bool,
}

struct TcpConn {
    src: SocketAddr,
    dst: SocketAddr,
    /// Some(..) once the connection was established and emitted to the caller.
    io: Option<TcpConnIo>,
}

/// A smoltcp socket bound to one remote endpoint: it receives what clients
/// send there and sends what comes back from there.
struct UdpSock {
    handle: SocketHandle,
    last_used: SmolInstant,
}

struct StackCore {
    device: PhyDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<SocketHandle, TcpConn>,
    tcp_tuples: HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    /// One udp socket per remote endpoint, shared by every client.
    udp_socks: HashMap<SocketAddr, UdpSock>,
    tcp_tx: mpsc::Sender<SmolTcpStream>,
    udp_tx: mpsc::Sender<SmolUdpPacket>,
    udp_out: mpsc::Receiver<UdpOut>,
    waker: Arc<LoopWaker>,
    mtu: usize,
    /// The time of the latest poll.
    now: SmolInstant,
}

impl StackCore {
    fn new(
        mtu: usize,
        tcp_tx: mpsc::Sender<SmolTcpStream>,
        udp_tx: mpsc::Sender<SmolUdpPacket>,
        udp_out: mpsc::Receiver<UdpOut>,
        waker: Arc<LoopWaker>,
    ) -> Self {
        let mut device = PhyDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        };

        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        // Accept-any-destination: smoltcp 0.12 accepts a packet to a foreign
        // address under any_ip only if the route lookup for that address
        // yields a gateway that IS one of the interface's own addresses. So
        // give the interface one address per family and default routes whose
        // gateway is that address.
        iface.set_any_ip(true);
        let v4 = std::net::Ipv4Addr::new(198, 18, 0, 1);
        let v6 = std::net::Ipv6Addr::new(0xfd00, 0x6d69, 0x656d, 0, 0, 0, 0, 1);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::from(v4), 32))
                .expect("iface v4 addr");
            addrs
                .push(IpCidr::new(IpAddress::from(v6), 128))
                .expect("iface v6 addr");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(v4)
            .expect("default v4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(v6)
            .expect("default v6 route");

        Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            tcp_tuples: HashMap::new(),
            udp_socks: HashMap::new(),
            tcp_tx,
            udp_tx,
            udp_out,
            waker,
            mtu,
            now: SmolInstant::from_micros(0),
        }
    }

    /// Queue one raw IP packet read from the TUN. Scans it first so that a
    /// SYN / first UDP datagram has a socket ready before `iface.poll`
    /// processes the packet.
    fn push_rx(&mut self, pkt: Vec<u8>) {
        self.scan(&pkt);
        self.device.rx.push_back(pkt);
    }

    /// Pop one outbound IP packet destined for the TUN.
    fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.device.tx.pop_front()
    }

    /// Run one full stack iteration: ingress, service sockets, egress.
    /// Returns the delay until smoltcp next needs to be polled.
    fn poll(&mut self, now: SmolInstant) -> Option<SmolDuration> {
        self.now = now;
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.service_tcp();
        self.service_udp(now);
        // Egress data the service pass moved into socket buffers.
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.iface.poll_delay(now, &self.sockets)
    }

    // -- packet pre-scan ----------------------------------------------------

    fn scan(&mut self, pkt: &[u8]) {
        if pkt.is_empty() {
            return;
        }
        match pkt[0] >> 4 {
            4 => {
                let Ok(ip) = Ipv4Packet::new_checked(pkt) else {
                    return;
                };
                // Only the first fragment carries the L4 header (and our
                // smoltcp build has no reassembly — fragments are dropped).
                if ip.frag_offset() != 0 || ip.more_frags() {
                    return;
                }
                let src = IpAddr::V4(ip.src_addr());
                let dst = IpAddr::V4(ip.dst_addr());
                match ip.next_header() {
                    IpProtocol::Tcp => self.scan_tcp(src, dst, ip.payload()),
                    IpProtocol::Udp => self.scan_udp(src, dst, ip.payload()),
                    _ => {} // TODO(icmp): surface echo requests to the caller
                }
            }
            6 => {
                let Ok(ip) = Ipv6Packet::new_checked(pkt) else {
                    return;
                };
                let src = IpAddr::V6(ip.src_addr());
                let dst = IpAddr::V6(ip.dst_addr());
                // Note: extension headers are not walked; TCP/UDP directly
                // after the fixed header covers real-world TUN traffic.
                match ip.next_header() {
                    IpProtocol::Tcp => self.scan_tcp(src, dst, ip.payload()),
                    IpProtocol::Udp => self.scan_udp(src, dst, ip.payload()),
                    _ => {} // TODO(icmp)
                }
            }
            _ => {}
        }
    }

    fn scan_tcp(&mut self, src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) {
        let Ok(tcp_pkt) = TcpPacket::new_checked(payload) else {
            return;
        };
        // Only a fresh SYN (no ACK) opens a new connection.
        if !tcp_pkt.syn() || tcp_pkt.ack() {
            return;
        }
        let src = SocketAddr::new(src_ip, tcp_pkt.src_port());
        let dst = SocketAddr::new(dst_ip, tcp_pkt.dst_port());
        if dst.port() == 0 || !is_unicast(dst_ip) {
            return;
        }
        if self.tcp_tuples.contains_key(&(src, dst)) {
            return; // SYN retransmission for a socket we already created
        }

        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF]),
            tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF]),
        );
        sock.set_nagle_enabled(false);
        sock.set_timeout(Some(SmolDuration::from_secs(TCP_TIMEOUT_SECS)));
        if let Err(e) = sock.listen(dst) {
            debug!("smol: listen {dst} failed: {e:?}");
            return;
        }
        let handle = self.sockets.add(sock);
        self.tcp_tuples.insert((src, dst), handle);
        self.tcp.insert(handle, TcpConn { src, dst, io: None });
        trace!("smol: new TCP socket for {src} -> {dst}");
    }

    fn scan_udp(&mut self, _src_ip: IpAddr, dst_ip: IpAddr, payload: &[u8]) {
        let Ok(udp_pkt) = UdpPacket::new_checked(payload) else {
            return;
        };
        let dst = SocketAddr::new(dst_ip, udp_pkt.dst_port());
        self.udp_socket(dst);
    }

    /// The socket bound to `endpoint`, created if there is none yet.
    fn udp_socket(&mut self, endpoint: SocketAddr) -> Option<SocketHandle> {
        if let Some(sock) = self.udp_socks.get(&endpoint) {
            return Some(sock.handle);
        }
        if endpoint.port() == 0 || !is_unicast(endpoint.ip()) {
            return None;
        }

        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_ENTRIES],
            vec![0u8; UDP_PAYLOAD_BUF],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_ENTRIES],
            vec![0u8; UDP_PAYLOAD_BUF],
        );
        let mut sock = udp::Socket::new(rx, tx);
        if let Err(e) = sock.bind(endpoint) {
            debug!("smol: udp bind {endpoint} failed: {e:?}");
            return None;
        }
        let handle = self.sockets.add(sock);
        self.udp_socks.insert(
            endpoint,
            UdpSock {
                handle,
                last_used: self.now,
            },
        );
        trace!("smol: new UDP socket for {endpoint}");
        Some(handle)
    }

    // -- TCP servicing ------------------------------------------------------

    fn service_tcp(&mut self) {
        let mut dead: Vec<SocketHandle> = Vec::new();

        for (&handle, conn) in self.tcp.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);

            // Newly established -> emit a stream to the caller. CloseWait
            // covers a client that sent data + FIN before we serviced.
            if conn.io.is_none()
                && matches!(
                    sock.state(),
                    tcp::State::Established | tcp::State::CloseWait
                )
            {
                let (to_app, app_rx) = mpsc::channel(CHAN_CAP);
                let (app_tx, from_app) = mpsc::channel::<AppMsg>(CHAN_CAP);
                let stream = SmolTcpStream {
                    src: conn.src,
                    dst: conn.dst,
                    rx: app_rx,
                    tx: PollSender::new(app_tx),
                    waker: self.waker.clone(),
                    read_buf: Vec::new(),
                    read_pos: 0,
                    shutdown_sent: false,
                };
                if self.tcp_tx.try_send(stream).is_err() {
                    // Caller can't keep up with accepts: refuse the connection.
                    warn!(
                        "smol: accept queue full, aborting {} -> {}",
                        conn.src, conn.dst
                    );
                    sock.abort();
                    dead.push(handle);
                    continue;
                }
                debug!("smol: TCP established {} -> {}", conn.src, conn.dst);
                conn.io = Some(TcpConnIo {
                    to_app: Some(to_app),
                    from_app,
                    pending: Vec::new(),
                    pending_pos: 0,
                    write_done: false,
                    close_called: false,
                });
            }

            if let Some(io) = conn.io.as_mut() {
                // socket -> app
                if let Some(tx) = io.to_app.as_ref() {
                    let mut app_gone = false;
                    while sock.can_recv() {
                        match tx.try_reserve() {
                            Ok(permit) => {
                                let data = sock
                                    .recv(|buf| (buf.len(), buf.to_vec()))
                                    .unwrap_or_default();
                                if data.is_empty() {
                                    break;
                                }
                                permit.send(data);
                            }
                            // App is slow: leave the data in the smoltcp
                            // receive buffer so the TCP window closes and the
                            // client backs off. Correct backpressure.
                            Err(mpsc::error::TrySendError::Full(_)) => break,
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                app_gone = true;
                                break;
                            }
                        }
                    }
                    if app_gone {
                        io.to_app = None;
                    } else if !sock.may_recv() && !sock.can_recv() {
                        // Peer half-closed and buffer drained: EOF to the app.
                        io.to_app = None;
                    }
                } else {
                    // App reader is gone; discard inbound so the window
                    // doesn't stall the peer while writes drain.
                    while sock.can_recv() {
                        if sock.recv(|buf| (buf.len(), ())).is_err() {
                            break;
                        }
                    }
                }

                // app -> socket (the datapath the old stack broke)
                loop {
                    if io.pending_pos < io.pending.len() {
                        if !sock.can_send() {
                            break;
                        }
                        match sock.send_slice(&io.pending[io.pending_pos..]) {
                            Ok(n) => {
                                io.pending_pos += n;
                                if io.pending_pos < io.pending.len() {
                                    break; // send buffer full again
                                }
                                io.pending.clear();
                                io.pending_pos = 0;
                            }
                            Err(_) => {
                                // Send half no longer open (reset/close).
                                io.write_done = true;
                                io.pending.clear();
                                io.pending_pos = 0;
                                break;
                            }
                        }
                    }
                    if io.write_done {
                        break;
                    }
                    match io.from_app.try_recv() {
                        Ok(AppMsg::Data(data)) => {
                            io.pending = data;
                            io.pending_pos = 0;
                        }
                        Ok(AppMsg::Shutdown) => {
                            io.write_done = true;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            // Stream dropped: flush what we have, then FIN.
                            io.write_done = true;
                        }
                    }
                }

                // Half-close towards the client once all app data is flushed.
                if io.write_done && io.pending_pos >= io.pending.len() && !io.close_called {
                    sock.close();
                    io.close_called = true;
                }
            }

            if sock.state() == tcp::State::Closed {
                dead.push(handle);
            }
        }

        for handle in dead {
            if let Some(conn) = self.tcp.remove(&handle) {
                trace!("smol: TCP closed {} -> {}", conn.src, conn.dst);
                self.tcp_tuples.remove(&(conn.src, conn.dst));
            }
            self.sockets.remove(handle);
        }
    }

    // -- UDP servicing ------------------------------------------------------

    fn service_udp(&mut self, now: SmolInstant) {
        // Inbound: socket -> app. A full channel drops the datagram.
        for (&dst, sock) in self.udp_socks.iter_mut() {
            let socket = self.sockets.get_mut::<udp::Socket>(sock.handle);
            while let Ok((buf, meta)) = socket.recv() {
                sock.last_used = now;
                let _ = self.udp_tx.try_send(SmolUdpPacket {
                    src: endpoint_to_sockaddr(meta.endpoint),
                    dst,
                    data: buf.to_vec(),
                });
            }
        }

        // Outbound: app -> the socket bound to the datagram's source.
        while let Ok(out) = self.udp_out.try_recv() {
            let Some(handle) = self.udp_socket(out.from) else {
                debug!(
                    "smol: udp from {} to {} dropped: unusable source",
                    out.from, out.to
                );
                continue;
            };
            if let Some(sock) = self.udp_socks.get_mut(&out.from) {
                sock.last_used = now;
            }
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if let Err(e) = socket.send_slice(&out.data, IpEndpoint::from(out.to)) {
                debug!("smol: udp from {} to {} dropped: {e:?}", out.from, out.to);
            }
        }

        // A socket nothing has passed through for a while is closed; the
        // next datagram for its endpoint makes a new one.
        let sockets = &mut self.sockets;
        self.udp_socks.retain(|endpoint, sock| {
            let socket = sockets.get::<udp::Socket>(sock.handle);
            if now - sock.last_used < UDP_SOCKET_IDLE
                || socket.can_recv()
                || socket.send_queue() > 0
            {
                return true;
            }
            trace!("smol: UDP socket for {endpoint} reaped");
            sockets.remove(sock.handle);
            false
        });
    }
}

fn endpoint_to_sockaddr(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(ep.addr.into(), ep.port)
}

fn is_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_broadcast() && !v4.is_unspecified(),
        IpAddr::V6(v6) => !v6.is_multicast() && !v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Poll thread
// ---------------------------------------------------------------------------

fn run_loop(tun: TunDevice, mut core: StackCore, waker: Arc<LoopWaker>) {
    let tun_fd = tun.as_raw_fd();
    let wake_fd = waker.fd;
    let mut rbuf = vec![0u8; core.mtu + 64];
    // A TUN packet write that hit EWOULDBLOCK, retried when writable.
    let mut tx_backlog: Option<Vec<u8>> = None;

    info!("smol stack started (mtu {})", core.mtu);

    loop {
        // (a) Drain all readable TUN packets.
        loop {
            let n =
                unsafe { libc::read(tun_fd, rbuf.as_mut_ptr() as *mut libc::c_void, rbuf.len()) };
            if n > 0 {
                core.push_rx(rbuf[..n as usize].to_vec());
                continue;
            }
            if n == 0 {
                warn!("smol: TUN device closed, stack exiting");
                return;
            }
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::WouldBlock => break,
                io::ErrorKind::Interrupted => continue,
                _ => {
                    warn!("smol: TUN read error: {err}, stack exiting");
                    return;
                }
            }
        }

        // (b)+(c)+(d) Run smoltcp and service sockets.
        let delay = core.poll(SmolInstant::now());

        // (e) Flush outbound packets to the TUN.
        let mut want_writable = false;
        loop {
            let pkt = match tx_backlog.take() {
                Some(p) => p,
                None => match core.pop_tx() {
                    Some(p) => p,
                    None => break,
                },
            };
            let n = unsafe { libc::write(tun_fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::WouldBlock => {
                        tx_backlog = Some(pkt);
                        want_writable = true;
                        break;
                    }
                    io::ErrorKind::Interrupted => {
                        tx_backlog = Some(pkt);
                        continue;
                    }
                    _ => {
                        // Drop the packet (TCP will retransmit).
                        debug!("smol: TUN write error: {err}");
                    }
                }
            }
        }

        // Sleep until: TUN readable / (writable if backlogged) / an app
        // write wakes us / the next smoltcp timer fires.
        let timeout_ms = match delay {
            Some(d) => (d.total_micros().div_ceil(1000) as i64).clamp(0, MAX_POLL_MS) as i32,
            None => MAX_POLL_MS as i32,
        };
        let mut tun_events = libc::POLLIN;
        if want_writable {
            tun_events |= libc::POLLOUT;
        }
        let mut fds = [
            libc::pollfd {
                fd: tun_fd,
                events: tun_events,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                warn!("smol: poll(2) failed: {err}, stack exiting");
                return;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            waker.drain();
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            warn!("smol: TUN device error/hangup, stack exiting");
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: drive the phy directly with crafted packets to prove the datapath
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber, UdpRepr};
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const IPV4_HDR: usize = 20;

    fn test_core() -> (
        StackCore,
        mpsc::Receiver<SmolTcpStream>,
        mpsc::Receiver<SmolUdpPacket>,
    ) {
        let (core, tcp_rx, udp_rx, _) = test_core_with_udp_out();
        (core, tcp_rx, udp_rx)
    }

    fn test_core_with_udp_out() -> (
        StackCore,
        mpsc::Receiver<SmolTcpStream>,
        mpsc::Receiver<SmolUdpPacket>,
        UdpSender,
    ) {
        let (tcp_tx, tcp_rx) = mpsc::channel(16);
        let (udp_tx, udp_rx) = mpsc::channel(16);
        let (out_tx, out_rx) = mpsc::channel(16);
        let waker = Arc::new(LoopWaker::new().unwrap());
        let sender = UdpSender {
            tx: out_tx,
            waker: waker.clone(),
        };
        (
            StackCore::new(1500, tcp_tx, udp_tx, out_rx, waker),
            tcp_rx,
            udp_rx,
            sender,
        )
    }

    /// The UDP datagrams the stack put on the wire: (source, destination, payload).
    fn udp_on_wire(core: &mut StackCore) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
        drain_tx(core)
            .iter()
            .filter_map(|p| {
                let ip = Ipv4Packet::new_checked(&p[..]).ok()?;
                if ip.next_header() != IpProtocol::Udp {
                    return None;
                }
                let u = UdpPacket::new_checked(ip.payload()).ok()?;
                Some((
                    SocketAddr::new(Ipv4Addr::from(ip.src_addr()).into(), u.src_port()),
                    SocketAddr::new(Ipv4Addr::from(ip.dst_addr()).into(), u.dst_port()),
                    u.payload().to_vec(),
                ))
            })
            .collect()
    }

    /// Craft an IPv4+TCP packet with valid checksums.
    fn tcp4(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        control: TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let caps = ChecksumCapabilities::default();
        let tcp_repr = TcpRepr {
            src_port: src.1,
            dst_port: dst.1,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: if control == TcpControl::Syn {
                Some(1460)
            } else {
                None
            },
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip_repr = Ipv4Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut buf[IPV4_HDR..]),
            &IpAddress::from(src.0),
            &IpAddress::from(dst.0),
            &caps,
        );
        buf
    }

    /// Craft an IPv4+UDP packet with valid checksums.
    fn udp4(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
        let caps = ChecksumCapabilities::default();
        let udp_repr = UdpRepr {
            src_port: src.1,
            dst_port: dst.1,
        };
        let udp_len = udp_repr.header_len() + payload.len();
        let ip_repr = Ipv4Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Udp,
            payload_len: udp_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + udp_len];
        ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut buf[IPV4_HDR..]),
            &IpAddress::from(src.0),
            &IpAddress::from(dst.0),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &caps,
        );
        buf
    }

    struct TcpOut {
        syn: bool,
        ack: bool,
        fin: bool,
        seq: u32,
        ack_no: u32,
        src_port: u16,
        dst_port: u16,
        dst_addr: Ipv4Addr,
        payload: Vec<u8>,
    }

    fn parse_tcp4(pkt: &[u8]) -> Option<TcpOut> {
        let ip = Ipv4Packet::new_checked(pkt).ok()?;
        if ip.next_header() != IpProtocol::Tcp {
            return None;
        }
        let dst_addr = ip.dst_addr();
        let tcp_pkt = TcpPacket::new_checked(ip.payload()).ok()?;
        Some(TcpOut {
            syn: tcp_pkt.syn(),
            ack: tcp_pkt.ack(),
            fin: tcp_pkt.fin(),
            seq: tcp_pkt.seq_number().0 as u32,
            ack_no: tcp_pkt.ack_number().0 as u32,
            src_port: tcp_pkt.src_port(),
            dst_port: tcp_pkt.dst_port(),
            dst_addr,
            payload: tcp_pkt.payload().to_vec(),
        })
    }

    fn drain_tx(core: &mut StackCore) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(p) = core.pop_tx() {
            out.push(p);
        }
        out
    }

    const CLIENT: (Ipv4Addr, u16) = (Ipv4Addr::new(192, 168, 1, 100), 40000);
    const SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(1, 2, 3, 4), 80);

    /// Perform the 3-way handshake against the core. Returns (server ISS,
    /// emitted stream, current time).
    fn handshake(
        core: &mut StackCore,
        tcp_rx: &mut mpsc::Receiver<SmolTcpStream>,
    ) -> (u32, SmolTcpStream, SmolInstant) {
        let mut now = SmolInstant::from_millis(0);

        // SYN -> expect SYN-ACK
        core.push_rx(tcp4(CLIENT, SERVER, TcpControl::Syn, 1000, None, &[]));
        core.poll(now);
        let tx = drain_tx(core);
        let synack = tx
            .iter()
            .filter_map(|p| parse_tcp4(p))
            .find(|t| t.syn && t.ack)
            .expect("no SYN-ACK emitted in response to SYN");
        assert_eq!(synack.ack_no, 1001, "SYN-ACK must ack client ISS+1");
        assert_eq!(synack.src_port, SERVER.1);
        assert_eq!(synack.dst_port, CLIENT.1);
        assert_eq!(synack.dst_addr, CLIENT.0);
        let iss = synack.seq;

        // Handshake ACK -> stream must be emitted
        now += SmolDuration::from_millis(10);
        core.push_rx(tcp4(
            CLIENT,
            SERVER,
            TcpControl::None,
            1001,
            Some(iss.wrapping_add(1)),
            &[],
        ));
        core.poll(now);
        let stream = tcp_rx
            .try_recv()
            .expect("no stream emitted after handshake completion");
        assert_eq!(stream.src, SocketAddr::new(CLIENT.0.into(), CLIENT.1));
        assert_eq!(stream.dst, SocketAddr::new(SERVER.0.into(), SERVER.1));

        (iss, stream, now)
    }

    #[test]
    fn tcp_handshake_and_bidirectional_data() {
        let (mut core, mut tcp_rx, _udp_rx) = test_core();
        let (iss, mut stream, mut now) = handshake(&mut core, &mut tcp_rx);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // client -> app: inject a data segment, read it from the stream.
        core.push_rx(tcp4(
            CLIENT,
            SERVER,
            TcpControl::Psh,
            1001,
            Some(iss.wrapping_add(1)),
            b"ping",
        ));
        core.poll(now);
        let mut rb = [0u8; 16];
        let n = rt.block_on(stream.read(&mut rb)).unwrap();
        assert_eq!(&rb[..n], b"ping", "client data must reach the app stream");
        drain_tx(&mut core); // discard the ACK

        // app -> client: THE bug the old gvisor.rs had. Write to the stream,
        // poll, and require a real TCP data segment on the wire.
        rt.block_on(stream.write_all(b"pong")).unwrap();
        now += SmolDuration::from_millis(10);
        core.poll(now);
        let tx = drain_tx(&mut core);
        let data_pkt = tx
            .iter()
            .filter_map(|p| parse_tcp4(p))
            .find(|t| !t.payload.is_empty())
            .expect("app write did not become a TCP data segment");
        assert_eq!(data_pkt.payload, b"pong");
        assert_eq!(data_pkt.seq, iss.wrapping_add(1));
        assert_eq!(data_pkt.dst_port, CLIENT.1);
        assert_eq!(data_pkt.dst_addr, CLIENT.0);
        // client acks the data
        core.push_rx(tcp4(
            CLIENT,
            SERVER,
            TcpControl::None,
            1005,
            Some(iss.wrapping_add(5)),
            &[],
        ));
        now += SmolDuration::from_millis(10);
        core.poll(now);

        // shutdown -> FIN on the wire
        rt.block_on(stream.shutdown()).unwrap();
        now += SmolDuration::from_millis(10);
        core.poll(now);
        let tx = drain_tx(&mut core);
        assert!(
            tx.iter().filter_map(|p| parse_tcp4(p)).any(|t| t.fin),
            "shutdown must produce a FIN"
        );
    }

    #[test]
    fn tcp_client_fin_gives_eof_and_socket_is_reaped() {
        let (mut core, mut tcp_rx, _udp_rx) = test_core();
        let (iss, mut stream, mut now) = handshake(&mut core, &mut tcp_rx);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Client half-closes.
        core.push_rx(tcp4(
            CLIENT,
            SERVER,
            TcpControl::Fin,
            1001,
            Some(iss.wrapping_add(1)),
            &[],
        ));
        core.poll(now);
        let n = rt.block_on(stream.read(&mut [0u8; 8])).unwrap();
        assert_eq!(n, 0, "client FIN must surface as EOF");

        // App closes its side; stack sends FIN; client acks it.
        rt.block_on(stream.shutdown()).unwrap();
        now += SmolDuration::from_millis(10);
        core.poll(now);
        let tx = drain_tx(&mut core);
        let fin = tx
            .iter()
            .filter_map(|p| parse_tcp4(p))
            .find(|t| t.fin)
            .expect("no FIN after app shutdown");
        core.push_rx(tcp4(
            CLIENT,
            SERVER,
            TcpControl::None,
            1002,
            Some(fin.seq.wrapping_add(1)),
            &[],
        ));
        now += SmolDuration::from_millis(10);
        core.poll(now);

        // Socket must eventually be reaped (LastAck -> Closed on the ACK).
        assert!(
            core.tcp.is_empty() && core.tcp_tuples.is_empty(),
            "closed TCP socket must be removed from the maps (state leak)"
        );
    }

    #[test]
    fn tcp_syn_retransmission_does_not_duplicate_sockets() {
        let (mut core, _tcp_rx, _udp_rx) = test_core();
        let now = SmolInstant::from_millis(0);
        core.push_rx(tcp4(CLIENT, SERVER, TcpControl::Syn, 1000, None, &[]));
        core.push_rx(tcp4(CLIENT, SERVER, TcpControl::Syn, 1000, None, &[]));
        core.poll(now);
        assert_eq!(core.tcp.len(), 1);
        assert_eq!(core.tcp_tuples.len(), 1);
    }

    #[test]
    fn udp_datagrams_carry_both_addresses_and_replies_reach_the_wire() {
        let (mut core, _tcp_rx, mut udp_rx, out) = test_core_with_udp_out();
        let mut now = SmolInstant::from_millis(0);
        let client = SocketAddr::from(([192, 168, 1, 100], 50000));
        let dns = SocketAddr::from(([8, 8, 8, 8], 53));
        let v4 = |addr: SocketAddr| match addr {
            SocketAddr::V4(a) => (*a.ip(), a.port()),
            SocketAddr::V6(_) => unreachable!(),
        };

        core.push_rx(udp4(v4(client), v4(dns), b"query"));
        core.poll(now);
        let packet = udp_rx.try_recv().expect("no UDP datagram delivered");
        assert_eq!((packet.src, packet.dst), (client, dns));
        assert_eq!(packet.data, b"query");

        now += SmolDuration::from_millis(5);
        core.push_rx(udp4(v4(client), v4(dns), b"again"));
        core.poll(now);
        assert_eq!(udp_rx.try_recv().unwrap().data, b"again");

        // The answer goes back through the stack, sourced from the address
        // the client wrote to.
        assert!(out.try_send(dns, client, b"answer".to_vec()));
        now += SmolDuration::from_millis(5);
        core.poll(now);
        assert_eq!(
            udp_on_wire(&mut core),
            vec![(dns, client, b"answer".to_vec())]
        );

        // An idle socket is closed.
        assert_eq!(core.udp_socks.len(), 1);
        now += UDP_SOCKET_IDLE;
        core.poll(now);
        assert!(core.udp_socks.is_empty(), "idle UDP socket must be reaped");
    }

    #[test]
    fn udp_can_be_sent_from_an_address_the_client_never_wrote_to() {
        // Full cone: once a client socket has an outbound, any peer's
        // datagram is delivered to it, from that peer's own address.
        let (mut core, _tcp_rx, _udp_rx, out) = test_core_with_udp_out();
        let client = SocketAddr::from(([192, 168, 1, 100], 50000));
        let peer = SocketAddr::from(([203, 0, 113, 7], 40000));

        assert!(out.try_send(peer, client, b"unsolicited".to_vec()));
        core.poll(SmolInstant::from_millis(0));
        assert_eq!(
            udp_on_wire(&mut core),
            vec![(peer, client, b"unsolicited".to_vec())]
        );
    }

    #[test]
    fn udp_two_sources_same_destination_share_a_socket() {
        let (mut core, _tcp_rx, mut udp_rx) = test_core();
        let now = SmolInstant::from_millis(0);
        let dns = (Ipv4Addr::new(8, 8, 8, 8), 53);
        core.push_rx(udp4((Ipv4Addr::new(192, 168, 1, 100), 50000), dns, b"a"));
        core.push_rx(udp4((Ipv4Addr::new(192, 168, 1, 101), 50001), dns, b"b"));
        core.poll(now);
        let p1 = udp_rx.try_recv().expect("datagram 1");
        let p2 = udp_rx.try_recv().expect("datagram 2");
        assert_ne!(p1.src, p2.src);
        assert_eq!(p1.data, b"a");
        assert_eq!(p2.data, b"b");
        assert_eq!(core.udp_socks.len(), 1);
    }
}
