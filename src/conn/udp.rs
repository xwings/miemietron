//! UDP sessions.
//!
//! mihomo compat: tunnel.go `handleUDPConn` + tunnel/connection.go. There is
//! one session per client socket (the NAT table is keyed by the packet's
//! local address). Its first datagram is sniffed, matched against the rules
//! and dialed; every later datagram, whatever its destination, leaves through
//! the same outbound packet connection, and replies go back to the client
//! from the address they came from.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, timeout_at, Instant};
use tracing::{debug, warn};

use super::{
    chain_display, format_dial_error, inbound_type_display, log_metadata, ConnEntry,
    ConnectionInfo, ConnectionManager, ConnectionMetadata, Retry, Route, Traffic,
};
use crate::common::addr::Address;
use crate::proxy::OutboundPacketConn;
use crate::sniffer::{quic::QuicSniffer, SniffAttempt};

/// mihomo compat: tunnel.go `senderCapacity` — datagrams a session may have
/// waiting; one that finds the queue full is dropped.
pub const UDP_QUEUE_SIZE: usize = 128;
/// mihomo compat: tunnel.go `udpTimeout` — a session with nothing sent or
/// received for this long ends.
pub const UDP_TIMEOUT: Duration = Duration::from_secs(60);
/// mihomo compat: `C.DefaultUDPTimeout`, the budget for dialing the outbound.
const UDP_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SNIFF_BYTES: usize = 256 * 1024;
const MAX_SNIFF_PACKETS: usize = 64;
// mihomo compat: component/sniffer/quic_sniffer.go quicWaitConn.
const QUIC_WAIT: Duration = Duration::from_secs(3);

/// A datagram as the client addressed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub dst: SocketAddr,
    /// The name the client gave instead of an address (SOCKS5 domain
    /// target); `dst` then carries the port and an unspecified IP.
    pub host: Option<String>,
    pub data: Vec<u8>,
}

impl UdpPacket {
    pub fn new(dst: SocketAddr, data: Vec<u8>) -> Self {
        Self {
            dst,
            host: None,
            data,
        }
    }
}

/// Queue `packet` for the session of `key`, creating the queue when there is
/// none. Returns the new queue's ends when a session has to be started for
/// it. A full queue drops the datagram; a closed one is replaced without
/// losing the datagram.
pub fn enqueue<K: Eq + Hash>(
    sessions: &dashmap::DashMap<K, mpsc::Sender<UdpPacket>>,
    key: K,
    packet: UdpPacket,
) -> Option<(mpsc::Sender<UdpPacket>, mpsc::Receiver<UdpPacket>)> {
    let create = |packet| {
        let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let _ = tx.try_send(packet);
        (tx, rx)
    };
    match sessions.entry(key) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => match entry.get().try_send(packet) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => None,
            Err(mpsc::error::TrySendError::Closed(packet)) => {
                let (tx, rx) = create(packet);
                entry.insert(tx.clone());
                Some((tx, rx))
            }
        },
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            let (tx, rx) = create(packet);
            entry.insert(tx.clone());
            Some((tx, rx))
        }
    }
}

/// The client socket a session belongs to.
pub struct UdpInbound {
    pub src: SocketAddr,
    pub conn_type: &'static str,
}

struct SniffedPackets {
    packets: Vec<UdpPacket>,
    host: Option<String>,
}

/// mihomo compat: quic_sniffer.go `quicPacketSender` — every datagram of the
/// client socket feeds the sniffer until it has an answer or gives up.
async fn sniff_packets(first: UdpPacket, rx: &mut mpsc::Receiver<UdpPacket>) -> SniffedPackets {
    let deadline = Instant::now() + QUIC_WAIT;
    let mut sniffer = QuicSniffer::new();
    let mut bytes = first.data.len();
    let mut packets = vec![first];
    let host = loop {
        match sniffer.sniff(&packets.last().unwrap().data) {
            SniffAttempt::Found(host) => break Some(host),
            SniffAttempt::Fail => break None,
            SniffAttempt::NeedMore(_) => {}
        }
        if packets.len() >= MAX_SNIFF_PACKETS || bytes >= MAX_SNIFF_BYTES {
            break None;
        }
        match timeout_at(deadline, rx.recv()).await {
            Ok(Some(packet)) => {
                bytes += packet.data.len();
                packets.push(packet);
            }
            _ => break None,
        }
    };
    SniffedPackets { packets, host }
}

/// The routing decision for a session's first datagram.
pub(super) struct UdpRoute {
    pub route: Route,
    pub mode: String,
    /// The destination host: given by the inbound, mapped back from the
    /// address, or sniffed.
    pub domain: Option<String>,
    /// The destination address after the rules ran: the client's own, a
    /// `hosts` entry, or what a rule had resolved. None when only the host
    /// is known.
    pub dst_ip: Option<IpAddr>,
}

/// Where the destinations a client socket addresses really go, and back.
///
/// mihomo compat: tunnel/connection.go `packetSender` — `originToTarget`
/// keyed by the metadata's host-or-address, `targetToOrigin` for the reply
/// path, each record written only while it is missing.
struct Targets {
    dns: Arc<crate::dns::DnsResolver>,
    config: Arc<crate::config::MiemieConfig>,
    map: parking_lot::Mutex<Mapping>,
    /// The first datagram's target, for a reply that names no address.
    first: SocketAddr,
}

#[derive(Default)]
struct Mapping {
    origin_to_target: HashMap<String, IpAddr>,
    target_to_origin: HashMap<IpAddr, IpAddr>,
}

/// mihomo compat: `metadata.String()` — the host, else the address.
fn origin_key(packet: &UdpPacket) -> String {
    match &packet.host {
        Some(host) => host.clone(),
        None => packet.dst.ip().to_string(),
    }
}

/// The address a datagram was sent to, if the client gave one.
fn origin_ip(packet: &UdpPacket) -> Option<IpAddr> {
    packet.host.is_none().then(|| packet.dst.ip())
}

impl Targets {
    fn new(
        dns: Arc<crate::dns::DnsResolver>,
        config: Arc<crate::config::MiemieConfig>,
        first: &UdpPacket,
        target: IpAddr,
    ) -> Self {
        let targets = Self {
            dns,
            config,
            map: parking_lot::Mutex::new(Mapping::default()),
            first: SocketAddr::new(target, first.dst.port()),
        };
        targets.add(first, target);
        targets
    }

    fn add(&self, packet: &UdpPacket, target: IpAddr) {
        let mut map = self.map.lock();
        map.origin_to_target
            .entry(origin_key(packet))
            .or_insert(target);
        if let Some(origin) = origin_ip(packet) {
            map.target_to_origin.entry(target).or_insert(origin);
        }
    }

    /// mihomo compat: `processPacket` — a destination seen before goes where
    /// it went before; a new one is mapped (preHandleMetadata), dialed by
    /// address when it has a real one (`Pure`) and resolved otherwise
    /// (`ResolveUDP`).
    async fn target_of(&self, packet: &UdpPacket) -> Result<SocketAddr> {
        let known = self
            .map
            .lock()
            .origin_to_target
            .get(&origin_key(packet))
            .copied();
        let ip = match known {
            Some(ip) => ip,
            None => {
                let ip = resolve_destination(&self.dns, &self.config, packet).await?;
                self.add(packet, ip);
                ip
            }
        };
        Ok(SocketAddr::new(ip, packet.dst.port()))
    }

    /// mihomo compat: `RestoreReadFrom` — a reply from an address a
    /// destination was mapped to is shown as coming from that destination.
    fn restore(&self, from: SocketAddr) -> SocketAddr {
        let ip = from.ip().to_canonical();
        let ip = self
            .map
            .lock()
            .target_to_origin
            .get(&ip)
            .copied()
            .unwrap_or(ip);
        SocketAddr::new(ip, from.port())
    }
}

/// The address a datagram goes to, before any rule has had a say.
async fn resolve_destination(
    dns: &crate::dns::DnsResolver,
    config: &crate::config::MiemieConfig,
    packet: &UdpPacket,
) -> Result<IpAddr> {
    let ip = packet.dst.ip();
    let host = match &packet.host {
        Some(host) => host.clone(),
        None => match dns.reverse_lookup(&ip) {
            Some(host) if dns.is_fake_ip(&ip) => host,
            // A real address that happens to have a name: `Pure()` drops the
            // name again, unless `hosts` points it elsewhere.
            Some(host) => return Ok(super::hosts_ip(config, dns, Some(&host)).unwrap_or(ip)),
            None if dns.is_fake_ip(&ip) => return Err(anyhow!("fake DNS record {} missing", ip)),
            None => return Ok(ip),
        },
    };
    resolve_host(dns, config, &host).await
}

/// mihomo compat: adapter/outbound/base.go `ResolveUDP`.
async fn resolve_host(
    dns: &crate::dns::DnsResolver,
    config: &crate::config::MiemieConfig,
    host: &str,
) -> Result<IpAddr> {
    if let Some(ip) = super::hosts_ip(config, dns, Some(host)) {
        return Ok(ip);
    }
    dns.resolve_real_ip(host)
        .await
        .map_err(|e| anyhow!("can't resolve ip: {e}"))
}

/// Removes a session from `/connections` however it ends.
struct Tracked<'a> {
    manager: &'a ConnectionManager,
    id: Arc<str>,
    closer: tokio::task::JoinHandle<()>,
}

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        self.closer.abort();
        if self.manager.connections.remove(&self.id).is_some() {
            self.manager.app.stats.remove_connection();
        }
    }
}

impl ConnectionManager {
    /// Run the session of one client socket: sniff, route and dial with its
    /// first datagram, then relay until it has been idle for [`UDP_TIMEOUT`],
    /// the outbound fails, or `rx` closes. `reply` delivers a datagram to the
    /// client as coming from the given address.
    pub async fn handle_udp<F, Fut>(
        &self,
        inbound: UdpInbound,
        mut rx: mpsc::Receiver<UdpPacket>,
        reply: F,
    ) -> Result<()>
    where
        F: Fn(Vec<u8>, SocketAddr) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let UdpInbound { src, conn_type } = inbound;
        let Some(first) = rx.recv().await else {
            return Ok(());
        };
        let config = self.app.config();
        let dns = self.app.dns_resolver();
        let dst = first.dst;
        let inbound_domain = first.host.clone();
        let mut domain = inbound_domain
            .clone()
            .or_else(|| dns.reverse_lookup(&dst.ip()));
        let mut sniff_host = String::new();
        let mut sniff_overrode = false;
        let sniff = config.sniffer.as_ref();
        let policy = sniff.and_then(|s| s.protocol_override("QUIC", dst.port()));
        let should_sniff = sniff.is_some_and(|s| {
            (domain.is_none() && s.parse_pure_ip)
                || (inbound_domain.is_none()
                    && domain.is_some()
                    && !dns.is_fake_ip(&dst.ip())
                    && s.force_dns_mapping)
                || domain
                    .as_deref()
                    .is_some_and(|host| s.is_force_domain(host))
        });
        let packets = if policy.is_some() && should_sniff {
            let sniffed = sniff_packets(first, &mut rx).await;
            if let Some(host) = sniffed.host.filter(|host| {
                crate::sniffer::is_domain_name(host)
                    && host.parse::<std::net::IpAddr>().is_err()
                    && !sniff.unwrap().is_skip_domain(host)
            }) {
                debug!(
                    "[Sniffer] Sniff UDP [{}]-->[{}] success, domain [{}]",
                    src, dst, host
                );
                sniff_host = host.clone();
                if policy == Some(true) {
                    domain = Some(host);
                    sniff_overrode = true;
                }
            }
            sniffed.packets
        } else {
            vec![first]
        };

        if domain.is_none() && dns.is_fake_ip(&dst.ip()) {
            return Err(anyhow!("fake DNS record {} missing", dst.ip()));
        }
        let UdpRoute {
            route,
            mode,
            domain,
            dst_ip,
        } = self
            .resolve_udp_route(src, dst, conn_type, domain, sniff_overrode)
            .await;

        // mihomo compat: RemoteAddress() — what the client asked for, by name
        // when it has one.
        let remote = match &domain {
            Some(host) => format!("{}:{}", host, dst.port()),
            None => dst.to_string(),
        };

        // mihomo compat: `retry(ctx, proxy.ListenPacketContext, logMetadataErr)`
        // under DefaultUDPTimeout. Each attempt goes through the rule's target
        // again, so the groups on the way select afresh, are touched, and
        // hear about a failure.
        let proxies = self.app.proxy_manager();
        let mut retry = Retry::new(UDP_DIAL_TIMEOUT);
        let (outbound, path, target) = loop {
            let Some(remaining) = retry.remaining() else {
                return Err(retry.into_error());
            };
            let path = proxies.resolve_action_path(&route.action)?;
            path.touch();
            let dialed = timeout(remaining, async {
                // mihomo compat: the adapter's `ResolveUDP` — only a
                // destination without an address is resolved.
                let ip = match (dst_ip, &domain) {
                    (Some(ip), _) => ip,
                    (None, Some(host)) => resolve_host(&dns, &config, host).await?,
                    (None, None) => return Err(anyhow!("udp addr invalid")),
                };
                let target = SocketAddr::new(ip, dst.port());
                let outbound = path
                    .handler
                    .connect_datagram_from(Some(src), &Address::ip(target), dns.clone())
                    .await?;
                Ok((outbound, target))
            })
            .await;
            let error = match dialed {
                Ok(Ok((outbound, target))) => break (outbound, path, target),
                Ok(Err(error)) => error,
                Err(_elapsed) => anyhow!("context deadline exceeded"),
            };
            // mihomo compat: the groups' `ListenPacketContext` report a
            // failure (`onDialFailed`) and nothing on success.
            path.on_dial_failed(&format!("{error:#}"));
            warn!("{}", format_dial_error("UDP", &route, src, &remote, &error));
            if !retry.again(error).await {
                return Err(retry.into_error());
            }
        };

        let chains = path.chains();
        log_metadata(
            "UDP",
            src,
            &remote,
            &mode,
            &route.rule_type,
            &route.rule_payload,
            &chain_display(&chains),
        );

        // mihomo compat: statistic.NewUDPTracker — the session is listed in
        // /connections and counted like a TCP connection.
        let id: Arc<str> = uuid::Uuid::new_v4().to_string().into();
        let traffic = Traffic::new(self.app.stats.clone(), 0);
        let closer = tokio::spawn(std::future::pending::<()>());
        self.connections.insert(
            id.clone(),
            ConnEntry {
                info: ConnectionInfo {
                    id: id.clone(),
                    metadata: ConnectionMetadata {
                        network: "udp",
                        conn_type: inbound_type_display(conn_type),
                        source_ip: src.ip(),
                        destination_ip: dst.ip(),
                        source_port: src.port(),
                        destination_port: dst.port(),
                        host: domain.clone().unwrap_or_default(),
                        dns_mode: if domain.is_some() { "fake-ip" } else { "" },
                        process_path: String::new(),
                        special_proxy: "",
                        special_rules: "",
                        remote_destination: target.to_string(),
                        dscp: 0,
                        sniff_host,
                    },
                    upload: 0,
                    download: 0,
                    start: chrono::Utc::now().to_rfc3339(),
                    chains,
                    rule: crate::rules::rule_type_display(&route.rule_type).to_string(),
                    rule_payload: route.rule_payload.clone(),
                },
                traffic: traffic.clone(),
                abort: closer.abort_handle(),
            },
        );
        self.app.stats.add_connection();
        let mut tracked = Tracked {
            manager: self,
            id,
            closer,
        };

        let targets = Targets::new(dns, config, &packets[0], target.ip());
        let outbound: Arc<dyn OutboundPacketConn> = Arc::from(outbound);
        let result = tokio::select! {
            result = relay_packets(outbound.as_ref(), &targets, packets, &mut rx, &traffic, reply) => result,
            // Closed through the controller.
            _ = &mut tracked.closer => Ok(()),
        };
        let _ = outbound.close().await;
        result
    }
}

async fn relay_packets<F, Fut>(
    outbound: &dyn OutboundPacketConn,
    targets: &Targets,
    packets: Vec<UdpPacket>,
    rx: &mut mpsc::Receiver<UdpPacket>,
    traffic: &Traffic,
    reply: F,
) -> Result<()>
where
    F: Fn(Vec<u8>, SocketAddr) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let (activity, mut last_activity) = watch::channel(Instant::now());
    let forward = async {
        let mut sniffed = packets.into_iter();
        loop {
            let packet = match sniffed.next() {
                Some(packet) => packet,
                None => match rx.recv().await {
                    Some(packet) => packet,
                    None => break,
                },
            };
            let target = match targets.target_of(&packet).await {
                Ok(target) => target,
                Err(error) => {
                    warn!("[UDP] Resolve Ip error: {}", error);
                    continue;
                }
            };
            // mihomo compat: processPacket drops handleUDPToRemote's error;
            // only a write that worked pushes the idle deadline out.
            match outbound.send_to(&packet.data, &Address::ip(target)).await {
                Ok(_) => {
                    traffic.uploaded(packet.data.len() as u64);
                    activity.send_replace(Instant::now());
                }
                Err(error) => debug!("UDP write to {} failed: {}", target, error),
            }
        }
    };
    let reverse = async {
        let mut buf = vec![0; 65535];
        loop {
            let (len, from) = outbound.recv_from(&mut buf).await?;
            activity.send_replace(Instant::now());
            traffic.downloaded(len as u64);
            let from = match from {
                Address::Ip(from) => from,
                other => {
                    warn!(
                        "server return a [{}] which isn't a UDP address, force replace to ({}), \
                         this may be caused by a wrongly implemented server",
                        other, targets.first
                    );
                    targets.first
                }
            };
            reply(buf[..len].to_vec(), targets.restore(from)).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };
    let idle = async {
        loop {
            let deadline = *last_activity.borrow_and_update() + UDP_TIMEOUT;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                changed = last_activity.changed() => if changed.is_err() { break },
            }
        }
    };
    // Poll both directions even while replaying the buffered Initial packets.
    // Waiting for a write before reading can deadlock UDP-over-stream peers
    // whose response fills their transport before they consume another packet.
    tokio::select! {
        _ = forward => Ok(()),
        result = reverse => result,
        _ = idle => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::manager;
    use super::*;
    use crate::sniffer::quic::test_support::initial_fragments;
    use tokio::net::UdpSocket;

    const CLIENT: &str = "127.0.0.1:12345";

    /// A session of `cm` for the client socket [`CLIENT`]: the queue feeding
    /// it, the replies it delivers, and its task.
    fn session(
        cm: ConnectionManager,
        conn_type: &'static str,
    ) -> (
        mpsc::Sender<UdpPacket>,
        mpsc::Receiver<(Vec<u8>, SocketAddr)>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let (reply_tx, reply_rx) = mpsc::channel(16);
        let task = tokio::spawn(async move {
            cm.handle_udp(
                UdpInbound {
                    src: CLIENT.parse().unwrap(),
                    conn_type,
                },
                rx,
                |data, from| {
                    let tx = reply_tx.clone();
                    async move {
                        tx.send((data, from)).await?;
                        Ok(())
                    }
                },
            )
            .await
        });
        (tx, reply_rx, task)
    }

    async fn within<T>(what: impl Future<Output = T>) -> T {
        timeout(Duration::from_secs(2), what).await.unwrap()
    }

    #[tokio::test]
    async fn fragmented_quic_routes_by_sni_and_replays_every_packet_in_order() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sink.local_addr().unwrap().port();
        let cm = manager(&format!(
            "hosts: {{quic.example.com: 127.0.0.1}}\nsniffer:\n  enable: true\n  sniff: {{QUIC: {{ports: [{port}]}}}}\nrules: ['IP-CIDR,203.0.113.0/24,REJECT,no-resolve', 'DOMAIN,quic.example.com,DIRECT', 'MATCH,REJECT']\n"
        )).await;
        let dst: SocketAddr = format!("203.0.113.1:{port}").parse().unwrap();
        let mut packets = initial_fragments("quic.example.com");
        packets.reverse(); // UDP fragments can arrive in either order.
        let expected = packets.clone();
        let (tx, mut replies, task) = session(cm, "tun");
        for packet in packets {
            tx.send(UdpPacket::new(dst, packet)).await.unwrap();
        }
        let mut buf = [0; 2048];
        let mut from = None;
        for packet in expected {
            let (len, peer) = within(sink.recv_from(&mut buf)).await.unwrap();
            assert_eq!(&buf[..len], &packet);
            from = Some(peer);
        }
        sink.send_to(b"response", from.unwrap()).await.unwrap();
        // The answer is shown as coming from the address the client wrote
        // to, not the one the sniffed name resolved to.
        assert_eq!(
            within(replies.recv()).await.unwrap(),
            (b"response".to_vec(), dst)
        );
        // Later client packets use the same routed flow without sniffing.
        tx.send(UdpPacket::new(dst, b"application".to_vec()))
            .await
            .unwrap();
        let (len, _) = within(sink.recv_from(&mut buf)).await.unwrap();
        assert_eq!(&buf[..len], b"application");
        task.abort();
    }

    #[tokio::test]
    async fn quic_override_and_skip_domain_control_routing() {
        for policy in [
            "override-destination: false",
            "skip-domain: ['+.example.com']",
            "parse-pure-ip: false",
        ] {
            let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = sink.local_addr().unwrap().port();
            let cm = Arc::new(manager(&format!(
                "sniffer:\n  enable: true\n  {policy}\n  sniff: {{QUIC: {{}}}}\nrules: ['DOMAIN,quic.example.com,DIRECT', 'MATCH,DIRECT']\n"
            )).await);
            let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
            for packet in initial_fragments("quic.example.com") {
                tx.send(UdpPacket::new(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    packet,
                ))
                .await
                .unwrap();
            }
            let running = cm.clone();
            let task = tokio::spawn(async move {
                running
                    .handle_udp(
                        UdpInbound {
                            src: CLIENT.parse().unwrap(),
                            conn_type: "socks5",
                        },
                        rx,
                        |_, _| async { Ok(()) },
                    )
                    .await
            });
            // The sniffed name must not have become the routing host.
            let mut buf = [0; 2048];
            within(sink.recv_from(&mut buf)).await.unwrap();
            let listed = cm.snapshot().connections;
            assert_eq!(listed.len(), 1, "{policy}");
            assert_eq!(listed[0].rule, "Match", "{policy}");
            assert_eq!(listed[0].metadata.host, "", "{policy}");
            task.abort();
        }
    }

    #[tokio::test]
    async fn incomplete_quic_times_out_and_replays_original_datagram() {
        let (tx, mut rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let first = UdpPacket::new(
            "203.0.113.1:443".parse().unwrap(),
            initial_fragments("quic.example.com").remove(0),
        );
        let started = Instant::now();
        let sniffed = sniff_packets(first.clone(), &mut rx).await;
        assert!(started.elapsed() >= QUIC_WAIT);
        assert!(started.elapsed() < QUIC_WAIT + Duration::from_secs(1));
        assert!(sniffed.host.is_none());
        assert_eq!(sniffed.packets, vec![first]);
        drop(tx);
    }

    #[tokio::test]
    async fn non_quic_fails_immediately_and_bounded_collection_keeps_originals() {
        let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let query = UdpPacket::new(dst, b"DNS query".to_vec());
        let sniffed = timeout(
            Duration::from_millis(100),
            sniff_packets(query.clone(), &mut rx),
        )
        .await
        .unwrap();
        assert!(sniffed.host.is_none());
        assert_eq!(sniffed.packets, vec![query]);
        let first = UdpPacket::new(dst, initial_fragments("quic.example.com").remove(0));
        let copies = first.clone();
        let sender = tokio::spawn(async move {
            for _ in 1..MAX_SNIFF_PACKETS {
                if tx.send(copies.clone()).await.is_err() {
                    break;
                }
            }
        });
        let sniffed = timeout(
            Duration::from_secs(1),
            sniff_packets(first.clone(), &mut rx),
        )
        .await
        .unwrap();
        assert!(sniffed.host.is_none());
        assert_eq!(sniffed.packets.len(), MAX_SNIFF_PACKETS);
        assert!(sniffed.packets.iter().all(|packet| packet == &first));
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn one_session_serves_every_destination_of_a_client_socket() {
        // mihomo's NAT table is keyed by the client socket: one outbound
        // packet conn, used for whatever the socket sends to, and open to
        // whoever answers it.
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cm = manager("rules: ['MATCH,DIRECT']\n").await;
        let (tx, mut replies, task) = session(cm, "tun");
        let mut buf = [0; 64];

        tx.send(UdpPacket::new(a.local_addr().unwrap(), b"to a".to_vec()))
            .await
            .unwrap();
        let (len, outbound) = within(a.recv_from(&mut buf)).await.unwrap();
        assert_eq!(&buf[..len], b"to a");

        tx.send(UdpPacket::new(b.local_addr().unwrap(), b"to b".to_vec()))
            .await
            .unwrap();
        let (len, same_outbound) = within(b.recv_from(&mut buf)).await.unwrap();
        assert_eq!(&buf[..len], b"to b");
        assert_eq!(same_outbound, outbound);

        // Each reply names where it came from, including a peer the client
        // never wrote to.
        for peer in [&b, &a, &stranger] {
            peer.send_to(b"hello", outbound).await.unwrap();
            assert_eq!(
                within(replies.recv()).await.unwrap(),
                (b"hello".to_vec(), peer.local_addr().unwrap())
            );
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_session_is_listed_and_counted_while_it_runs() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cm = Arc::new(manager("rules: ['MATCH,DIRECT']\n").await);
        let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let (reply_tx, mut replies) = mpsc::channel(1);
        let running = cm.clone();
        let task = tokio::spawn(async move {
            running
                .handle_udp(
                    UdpInbound {
                        src: CLIENT.parse().unwrap(),
                        conn_type: "tproxy",
                    },
                    rx,
                    |data, _| {
                        let tx = reply_tx.clone();
                        async move {
                            tx.send(data).await?;
                            Ok(())
                        }
                    },
                )
                .await
        });
        tx.send(UdpPacket::new(sink.local_addr().unwrap(), vec![7; 100]))
            .await
            .unwrap();
        let mut buf = [0; 128];
        let (_, outbound) = within(sink.recv_from(&mut buf)).await.unwrap();
        sink.send_to(&[9; 40], outbound).await.unwrap();
        within(replies.recv()).await.unwrap();

        let snapshot = cm.snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        let listed = &snapshot.connections[0];
        assert_eq!(listed.metadata.network, "udp");
        assert_eq!(listed.metadata.conn_type, "TProxy");
        assert_eq!(listed.chains, vec!["DIRECT".to_string()]);
        assert_eq!((listed.upload, listed.download), (100, 40));
        // The process totals move with the session, not at its end.
        assert_eq!((snapshot.upload_total, snapshot.download_total), (100, 40));

        // Closing it through the controller ends the session.
        assert!(cm.close_connection(&listed.id));
        within(task).await.unwrap().unwrap();
        assert!(cm.snapshot().connections.is_empty());
    }

    #[tokio::test]
    async fn replies_from_a_mapped_target_show_the_address_the_client_used() {
        let cm = manager("mode: rule\n").await;
        let fake: SocketAddr = "198.18.0.7:443".parse().unwrap();
        let real: IpAddr = "203.0.113.9".parse().unwrap();
        let targets = Targets::new(
            cm.app.dns_resolver(),
            cm.app.config(),
            &UdpPacket::new(fake, Vec::new()),
            real,
        );
        assert_eq!(
            targets
                .target_of(&UdpPacket::new(fake, Vec::new()))
                .await
                .unwrap(),
            SocketAddr::new(real, 443)
        );
        // Another port of the same destination goes to the same address.
        let other_port = UdpPacket::new("198.18.0.7:8443".parse().unwrap(), Vec::new());
        assert_eq!(
            targets.target_of(&other_port).await.unwrap(),
            SocketAddr::new(real, 8443)
        );
        assert_eq!(targets.restore(SocketAddr::new(real, 443)), fake);
        // An IPv4-mapped source is the IPv4 address.
        assert_eq!(
            targets.restore("[::ffff:203.0.113.9]:443".parse().unwrap()),
            fake
        );
        // Anyone else is who they are.
        let stranger: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        assert_eq!(targets.restore(stranger), stranger);

        // A destination given by name has no address to restore: its
        // replies carry the resolved one.
        let named = UdpPacket {
            dst: "0.0.0.0:53".parse().unwrap(),
            host: Some("dns.example".to_string()),
            data: Vec::new(),
        };
        let resolved: IpAddr = "192.0.2.53".parse().unwrap();
        targets.add(&named, resolved);
        assert_eq!(
            targets.target_of(&named).await.unwrap(),
            SocketAddr::new(resolved, 53)
        );
        assert_eq!(
            targets.restore(SocketAddr::new(resolved, 53)),
            SocketAddr::new(resolved, 53)
        );
    }

    #[tokio::test]
    async fn buffered_udp_writes_and_replies_progress_under_backpressure() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Backpressured {
            responses: tokio::sync::Notify,
            reads: AtomicUsize,
            writes: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl OutboundPacketConn for Backpressured {
            async fn send_to(&self, data: &[u8], _: &Address) -> Result<usize> {
                // A peer can consume another request only once its response
                // has been read. This models bounded duplex stream buffers.
                self.responses.notified().await;
                self.writes.fetch_add(1, Ordering::SeqCst);
                Ok(data.len())
            }
            async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                self.responses.notify_one();
                tokio::task::yield_now().await;
                buf[0] = 1;
                Ok((1, Address::ip("127.0.0.1:443".parse().unwrap())))
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let outbound = Backpressured {
            responses: tokio::sync::Notify::new(),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        };
        let cm = manager("mode: rule\n").await;
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let packet = |byte: u8| UdpPacket::new(dst, vec![byte]);
        let targets = Targets::new(cm.app.dns_resolver(), cm.app.config(), &packet(1), dst.ip());
        let traffic = Traffic::new(cm.app.stats.clone(), 0);
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(packet(3)).await.unwrap();
        drop(tx);
        timeout(
            Duration::from_secs(1),
            relay_packets(
                &outbound,
                &targets,
                vec![packet(1), packet(2)],
                &mut rx,
                &traffic,
                |_, _| async { Ok(()) },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(outbound.writes.load(Ordering::SeqCst), 3);
        assert!(outbound.reads.load(Ordering::SeqCst) >= 3);
        assert_eq!(traffic.upload(), 3);
    }

    #[tokio::test]
    async fn a_failed_write_does_not_end_the_session() {
        // tunnel/connection.go processPacket: `_ = handleUDPToRemote(...)`.
        struct Flaky {
            sent: parking_lot::Mutex<Vec<Vec<u8>>>,
        }
        #[async_trait::async_trait]
        impl OutboundPacketConn for Flaky {
            async fn send_to(&self, data: &[u8], _: &Address) -> Result<usize> {
                if data == b"lost" {
                    return Err(anyhow!("network unreachable"));
                }
                self.sent.lock().push(data.to_vec());
                Ok(data.len())
            }
            async fn recv_from(&self, _: &mut [u8]) -> Result<(usize, Address)> {
                std::future::pending().await
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let outbound = Flaky {
            sent: parking_lot::Mutex::new(Vec::new()),
        };
        let cm = manager("mode: rule\n").await;
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let packet = |data: &[u8]| UdpPacket::new(dst, data.to_vec());
        let targets = Targets::new(
            cm.app.dns_resolver(),
            cm.app.config(),
            &packet(b""),
            dst.ip(),
        );
        let traffic = Traffic::new(cm.app.stats.clone(), 0);
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(packet(b"second")).await.unwrap();
        drop(tx);
        relay_packets(
            &outbound,
            &targets,
            vec![packet(b"first"), packet(b"lost")],
            &mut rx,
            &traffic,
            |_, _| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(
            *outbound.sent.lock(),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
        assert_eq!(traffic.upload(), 11);
    }
}
