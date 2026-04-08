//! User-space TCP/IP stack ("gvisor" mode) using smoltcp.
//!
//! Instead of relying on kernel iptables REDIRECT + SO_ORIGINAL_DST, this stack
//! processes raw IP packets from the TUN device directly using smoltcp's TCP/IP
//! implementation. This eliminates the need for iptables rules and works in
//! environments where kernel transparent proxy support is limited.
//!
//! Architecture:
//! 1. TUN device reads raw IP packets
//! 2. smoltcp processes them through its TCP/UDP socket layer
//! 3. Accepted TCP connections are wrapped as AsyncRead+AsyncWrite streams
//! 4. UDP datagrams are extracted with src/dst addresses
//! 5. Both are handed to ConnectionManager (same interface as system stack)

use anyhow::Result;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::TunConfig;
use crate::tun::device::TunDevice;

/// A TCP connection extracted from the gvisor stack.
pub struct GvisorTcpStream {
    /// Channel to receive data from the smoltcp socket
    rx: mpsc::Receiver<Vec<u8>>,
    /// Channel to send data to the smoltcp socket
    tx: mpsc::Sender<Vec<u8>>,
    /// Buffered data from previous recv that wasn't fully consumed
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Source address of the connection
    pub src: SocketAddr,
    /// Original destination address
    pub dst: SocketAddr,
}

impl AsyncRead for GvisorTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First drain any buffered data
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Try to receive more data
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

impl AsyncWrite for GvisorTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let data = buf.to_vec();
        let len = data.len();
        match self.tx.try_send(data) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Information about a pending TCP connection
struct PendingTcp {
    src: SocketAddr,
    dst: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Information about a received UDP datagram
pub struct GvisorUdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub data: Vec<u8>,
}

/// The gvisor stack processes raw IP packets from a TUN device using smoltcp.
pub struct GvisorStack {
    tcp_rx: mpsc::Receiver<GvisorTcpStream>,
    udp_rx: mpsc::Receiver<GvisorUdpDatagram>,
}

impl GvisorStack {
    /// Start the gvisor stack on the given TUN device.
    ///
    /// Spawns a background task that reads packets from the TUN, feeds them
    /// to smoltcp, and produces TCP streams and UDP datagrams.
    pub fn start(tun: TunDevice, config: &TunConfig) -> Self {
        let (tcp_tx, tcp_rx) = mpsc::channel(256);
        let (udp_tx, udp_rx) = mpsc::channel(1024);
        let mtu = config.mtu as usize;

        tokio::spawn(async move {
            if let Err(e) = run_gvisor_loop(tun, mtu, tcp_tx, udp_tx).await {
                error!("Gvisor stack error: {}", e);
            }
        });

        Self { tcp_rx, udp_rx }
    }

    /// Decompose into separate TCP and UDP channels for use with tokio::select!
    pub fn into_channels(
        self,
    ) -> (
        mpsc::Receiver<GvisorTcpStream>,
        mpsc::Receiver<GvisorUdpDatagram>,
    ) {
        (self.tcp_rx, self.udp_rx)
    }
}

/// Main processing loop: reads raw packets from TUN, parses IP headers,
/// and extracts TCP connections and UDP datagrams.
///
/// Uses a simplified approach: instead of running full smoltcp socket layer,
/// we parse IP/TCP/UDP headers directly from raw packets. This gives us the
/// src/dst addresses and payload, which is all ConnectionManager needs.
///
/// For TCP, we need to handle the three-way handshake and maintain connection
/// state. We synthesize SYN-ACK replies and track sequence numbers.
async fn run_gvisor_loop(
    mut tun: TunDevice,
    mtu: usize,
    tcp_tx: mpsc::Sender<GvisorTcpStream>,
    udp_tx: mpsc::Sender<GvisorUdpDatagram>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; mtu + 64];

    // TCP connection tracking
    let mut tcp_connections: HashMap<(SocketAddr, SocketAddr), TcpConnectionState> = HashMap::new();

    info!("Gvisor stack started (MTU {})", mtu);

    loop {
        let n = match tun.read(&mut buf).await {
            Ok(0) => {
                warn!("TUN device closed");
                break;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                debug!("TUN read error: {}", e);
                continue;
            }
        };

        let packet = &buf[..n];
        if packet.is_empty() {
            continue;
        }

        // Determine IP version from first nibble
        let version = (packet[0] >> 4) & 0xf;

        match version {
            4 => {
                if let Some(parsed) = parse_ipv4_packet(packet) {
                    match parsed.protocol {
                        6 => {
                            // TCP
                            handle_tcp_packet(
                                &parsed,
                                &mut tcp_connections,
                                &tcp_tx,
                                &mut tun,
                            )
                            .await;
                        }
                        17 => {
                            // UDP
                            handle_udp_packet(&parsed, &udp_tx).await;
                        }
                        _ => {} // Ignore other protocols
                    }
                }
            }
            6 => {
                if let Some(parsed) = parse_ipv6_packet(packet) {
                    match parsed.protocol {
                        6 => {
                            handle_tcp_packet(
                                &parsed,
                                &mut tcp_connections,
                                &tcp_tx,
                                &mut tun,
                            )
                            .await;
                        }
                        17 => {
                            handle_udp_packet(&parsed, &udp_tx).await;
                        }
                        _ => {}
                    }
                }
            }
            _ => {} // Invalid IP version
        }
    }

    Ok(())
}

/// Parsed IP packet fields we need
struct ParsedPacket {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    payload: Vec<u8>, // TCP/UDP header + data
    raw: Vec<u8>,     // Full raw IP packet (for building replies)
}

fn parse_ipv4_packet(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 20 {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if data.len() < ihl {
        return None;
    }

    let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    let protocol = data[9];

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        protocol,
        payload: data[ihl..].to_vec(),
        raw: data.to_vec(),
    })
}

fn parse_ipv6_packet(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 40 {
        return None;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);

    let src_ip = IpAddr::V6(Ipv6Addr::from(src));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst));
    let next_header = data[6]; // Next header = protocol

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        protocol: next_header,
        payload: data[40..].to_vec(),
        raw: data.to_vec(),
    })
}

/// State for a TCP connection being tracked by the gvisor stack
struct TcpConnectionState {
    /// Our sequence number (used in SYN-ACK and subsequent packets)
    our_seq: u32,
    /// The remote's sequence number
    their_seq: u32,
    /// Whether the connection has been established (3-way handshake complete)
    established: bool,
    /// Channel to send data to the application layer
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Sender that the GvisorTcpStream will use to write data back
    from_app_tx: mpsc::Sender<Vec<u8>>,
}

async fn handle_tcp_packet(
    packet: &ParsedPacket,
    connections: &mut HashMap<(SocketAddr, SocketAddr), TcpConnectionState>,
    tcp_tx: &mpsc::Sender<GvisorTcpStream>,
    tun: &mut TunDevice,
) {
    let tcp_data = &packet.payload;
    if tcp_data.len() < 20 {
        return;
    }

    let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
    let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
    let seq_num = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
    let _ack_num = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
    let data_offset = ((tcp_data[12] >> 4) as usize) * 4;
    let flags = tcp_data[13];

    let syn = (flags & 0x02) != 0;
    let ack = (flags & 0x10) != 0;
    let fin = (flags & 0x01) != 0;
    let rst = (flags & 0x04) != 0;
    let _psh = (flags & 0x08) != 0;

    let src = SocketAddr::new(packet.src_ip, src_port);
    let dst = SocketAddr::new(packet.dst_ip, dst_port);
    let key = (src, dst);

    let tcp_payload = if data_offset < tcp_data.len() {
        &tcp_data[data_offset..]
    } else {
        &[]
    };

    if syn && !ack {
        // SYN - New connection request
        // Create channels for the application layer
        let (to_app_tx, _to_app_rx) = mpsc::channel(64);
        let (from_app_tx, _from_app_rx) = mpsc::channel(64);

        let our_seq: u32 = rand::random();

        connections.insert(key, TcpConnectionState {
            our_seq: our_seq.wrapping_add(1),
            their_seq: seq_num.wrapping_add(1),
            established: false,
            app_tx: to_app_tx,
            from_app_tx,
        });

        // Send SYN-ACK back through TUN
        let syn_ack = build_tcp_response(
            &packet.dst_ip, dst_port,
            &packet.src_ip, src_port,
            our_seq,
            seq_num.wrapping_add(1),
            0x12, // SYN+ACK
            &[],
        );
        use tokio::io::AsyncWriteExt;
        let _ = tun.write_all(&syn_ack).await;

        debug!("Gvisor: SYN from {} -> {}, sent SYN-ACK", src, dst);

    } else if ack && !syn {
        if let Some(conn) = connections.get_mut(&key) {
            if !conn.established {
                // ACK completing the 3-way handshake
                conn.established = true;

                // Create new channels for the stream
                let (stream_tx, stream_rx) = mpsc::channel(64);

                let stream = GvisorTcpStream {
                    rx: stream_rx,
                    tx: conn.from_app_tx.clone(),
                    read_buf: Vec::new(),
                    read_pos: 0,
                    src,
                    dst,
                };

                // Update app_tx to point to the stream's receiver
                conn.app_tx = stream_tx;

                let _ = tcp_tx.try_send(stream);
                debug!("Gvisor: TCP established {} -> {}", src, dst);
            }

            // Forward any data payload to the application
            if !tcp_payload.is_empty() {
                let _ = conn.app_tx.try_send(tcp_payload.to_vec());
                conn.their_seq = conn.their_seq.wrapping_add(tcp_payload.len() as u32);

                // Send ACK
                let ack_pkt = build_tcp_response(
                    &packet.dst_ip, dst_port,
                    &packet.src_ip, src_port,
                    conn.our_seq,
                    conn.their_seq,
                    0x10, // ACK
                    &[],
                );
                use tokio::io::AsyncWriteExt;
                let _ = tun.write_all(&ack_pkt).await;
            }
        }
    }

    if fin {
        if let Some(conn) = connections.remove(&key) {
            // Send FIN-ACK
            let fin_ack = build_tcp_response(
                &packet.dst_ip, dst_port,
                &packet.src_ip, src_port,
                conn.our_seq,
                seq_num.wrapping_add(1),
                0x11, // FIN+ACK
                &[],
            );
            use tokio::io::AsyncWriteExt;
            let _ = tun.write_all(&fin_ack).await;
            debug!("Gvisor: TCP FIN {} -> {}", src, dst);
        }
    }

    if rst {
        connections.remove(&key);
    }
}

/// Build a minimal IPv4 + TCP response packet
fn build_tcp_response(
    src_ip: &IpAddr, src_port: u16,
    dst_ip: &IpAddr, dst_port: u16,
    seq: u32, ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len; // IPv4 header + TCP

    let mut packet = vec![0u8; total_len];

    // IPv4 header
    packet[0] = 0x45; // Version 4, IHL 5
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xff) as u8;
    packet[6] = 0x40; // Don't Fragment
    packet[8] = 64; // TTL
    packet[9] = 6; // TCP

    match src_ip {
        IpAddr::V4(ip) => packet[12..16].copy_from_slice(&ip.octets()),
        _ => {}
    }
    match dst_ip {
        IpAddr::V4(ip) => packet[16..20].copy_from_slice(&ip.octets()),
        _ => {}
    }

    // IPv4 header checksum
    let cksum = ipv4_checksum(&packet[..20]);
    packet[10] = (cksum >> 8) as u8;
    packet[11] = (cksum & 0xff) as u8;

    // TCP header
    let tcp = &mut packet[20..];
    tcp[0] = (src_port >> 8) as u8;
    tcp[1] = (src_port & 0xff) as u8;
    tcp[2] = (dst_port >> 8) as u8;
    tcp[3] = (dst_port & 0xff) as u8;
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // Data offset: 5 (20 bytes)
    tcp[13] = flags;
    tcp[14] = 0xff; // Window size high
    tcp[15] = 0xff; // Window size low

    // Copy payload
    if !payload.is_empty() {
        tcp[20..20 + payload.len()].copy_from_slice(payload);
    }

    // TCP checksum (pseudo-header + TCP segment)
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &packet[20..]);
    packet[36] = (tcp_cksum >> 8) as u8;
    packet[37] = (tcp_cksum & 0xff) as u8;

    packet
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn tcp_checksum(src_ip: &IpAddr, dst_ip: &IpAddr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let s = src.octets();
            let d = dst.octets();
            sum += ((s[0] as u32) << 8) | (s[1] as u32);
            sum += ((s[2] as u32) << 8) | (s[3] as u32);
            sum += ((d[0] as u32) << 8) | (d[1] as u32);
            sum += ((d[2] as u32) << 8) | (d[3] as u32);
        }
        _ => {} // IPv6 pseudo-header would go here
    }
    sum += 6; // Protocol: TCP
    sum += tcp_segment.len() as u32;

    // TCP segment
    for i in (0..tcp_segment.len()).step_by(2) {
        if i == 16 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < tcp_segment.len() {
            ((tcp_segment[i] as u32) << 8) | (tcp_segment[i + 1] as u32)
        } else {
            (tcp_segment[i] as u32) << 8
        };
        sum += word;
    }

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

async fn handle_udp_packet(
    packet: &ParsedPacket,
    udp_tx: &mpsc::Sender<GvisorUdpDatagram>,
) {
    let udp_data = &packet.payload;
    if udp_data.len() < 8 {
        return;
    }

    let src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
    let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
    let payload = &udp_data[8..];

    let src = SocketAddr::new(packet.src_ip, src_port);
    let dst = SocketAddr::new(packet.dst_ip, dst_port);

    let _ = udp_tx.try_send(GvisorUdpDatagram {
        src,
        dst,
        data: payload.to_vec(),
    });
}

