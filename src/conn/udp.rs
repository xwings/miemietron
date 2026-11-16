//! UDP sniffing happens once, before rule matching and outbound creation.

use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout_at, Instant};
use tracing::debug;

use super::ConnectionManager;
use crate::common::addr::Address;
use crate::proxy::OutboundPacketConn;
use crate::sniffer::{quic::QuicSniffer, SniffAttempt};

// Keep pending flows bounded while their ClientHello or outbound is arriving.
pub const UDP_QUEUE_SIZE: usize = 32;
const MAX_SNIFF_BYTES: usize = 256 * 1024;
const MAX_SNIFF_PACKETS: usize = 64;
// mihomo compat: component/sniffer/quic_sniffer.go quicWaitConn.
const QUIC_WAIT: Duration = Duration::from_secs(3);

/// Install one worker queue before routing, so later fragments cannot create
/// competing sessions. A full UDP queue drops that datagram; a closed one is
/// replaced without losing the first datagram of the new session.
pub fn enqueue<K: Eq + Hash>(
    sessions: &dashmap::DashMap<K, mpsc::Sender<Vec<u8>>>,
    key: K,
    packet: Vec<u8>,
) -> Option<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)> {
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

pub struct UdpInbound {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub conn_type: &'static str,
    pub domain: Option<String>,
}

struct SniffedPackets {
    packets: Vec<Vec<u8>>,
    host: Option<String>,
}

async fn sniff_packets(first: Vec<u8>, rx: &mut mpsc::Receiver<Vec<u8>>) -> SniffedPackets {
    let deadline = Instant::now() + QUIC_WAIT;
    let mut sniffer = QuicSniffer::new();
    let mut bytes = first.len();
    let mut packets = vec![first];
    let host = loop {
        match sniffer.sniff(packets.last().unwrap()) {
            SniffAttempt::Found(host) => break Some(host),
            SniffAttempt::Fail => break None,
            SniffAttempt::NeedMore(_) => {}
        }
        if packets.len() >= MAX_SNIFF_PACKETS || bytes >= MAX_SNIFF_BYTES {
            break None;
        }
        match timeout_at(deadline, rx.recv()).await {
            Ok(Some(packet)) => {
                bytes += packet.len();
                packets.push(packet);
            }
            _ => break None,
        }
    };
    SniffedPackets { packets, host }
}

impl ConnectionManager {
    /// All UDP inbounds use the same queued sniff/route/dial/relay path. The
    /// listener owns only packet framing and delivering replies to its client.
    pub async fn handle_udp<F, Fut>(
        &self,
        inbound: UdpInbound,
        mut rx: mpsc::Receiver<Vec<u8>>,
        idle_timeout: Duration,
        reply: F,
    ) -> Result<()>
    where
        F: Fn(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let UdpInbound {
            src,
            dst,
            conn_type,
            domain: inbound_domain,
        } = inbound;
        let Some(first) = rx.recv().await else {
            return Ok(());
        };
        let config = self.app.config();
        let dns = self.app.dns_resolver();
        let mut domain = inbound_domain
            .clone()
            .or_else(|| dns.reverse_lookup(&dst.ip()));
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
        let (action, domain) = self
            .resolve_udp_action(src, dst, conn_type, domain, sniff_overrode)
            .await;
        let target = if let Some(ip) = super::hosts_ip(&config, &dns, domain.as_deref()) {
            Address::ip(SocketAddr::new(ip, dst.port()))
        } else {
            match domain {
                Some(host) => Address::domain(&host, dst.port()),
                None => Address::ip(dst),
            }
        };
        let proxies = self.app.proxy_manager();
        let outbound: std::sync::Arc<dyn OutboundPacketConn> = match &action {
            crate::rules::Action::Proxy(name) => proxies.dial_proxy_udp(name, &target, dns).await?,
            _ => std::sync::Arc::from(
                proxies
                    .resolve_action(&action)?
                    .connect_datagram(&target, dns)
                    .await?,
            ),
        };
        relay_packets(
            outbound.as_ref(),
            &target,
            packets,
            &mut rx,
            idle_timeout,
            reply,
        )
        .await
    }
}

async fn relay_packets<F, Fut>(
    outbound: &dyn OutboundPacketConn,
    target: &Address,
    packets: Vec<Vec<u8>>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    idle_timeout: Duration,
    reply: F,
) -> Result<()>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let (activity, mut last_activity) = watch::channel(Instant::now());
    let forward = async {
        for packet in packets {
            outbound.send_to(&packet, target).await?;
            activity.send_replace(Instant::now());
        }
        while let Some(packet) = rx.recv().await {
            outbound.send_to(&packet, target).await?;
            activity.send_replace(Instant::now());
        }
        Ok::<_, anyhow::Error>(())
    };
    let reverse = async {
        let mut buf = vec![0; 65535];
        loop {
            let (len, _) = outbound.recv_from(&mut buf).await?;
            activity.send_replace(Instant::now());
            reply(buf[..len].to_vec()).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };
    let idle = async {
        loop {
            let deadline = *last_activity.borrow_and_update() + idle_timeout;
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
        result = forward => result,
        result = reverse => result,
        _ = idle => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniffer::quic::test_support::initial_fragments;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    async fn manager(yaml: &str) -> ConnectionManager {
        let config = crate::MiemieConfig::parse_str(yaml).unwrap();
        let home = tempfile::tempdir().unwrap();
        let state_store = Arc::new(crate::proxy_group::proxy_state::ProxyStateStore::new());
        let (dns, rules, proxies) =
            crate::build_components(&config, home.path(), state_store.clone())
                .await
                .unwrap();
        let (restart_tx, _) = mpsc::channel(1);
        let state = Arc::new(crate::AppState {
            config: parking_lot::RwLock::new(Arc::new(config.clone())),
            rule_engine: parking_lot::RwLock::new(rules),
            proxy_manager: parking_lot::RwLock::new(Arc::new(proxies)),
            dns_resolver: parking_lot::RwLock::new(Arc::new(dns)),
            stats: Arc::new(super::super::StatsManager::new()),
            runtime_config: parking_lot::RwLock::new(crate::api::RuntimeConfig {
                mode: config.mode,
                log_level: config.log_level,
                allow_lan: None,
                find_process_mode: None,
                sniffing: None,
                tcp_concurrent: None,
            }),
            home_dir: home.path().to_path_buf(),
            config_path: parking_lot::RwLock::new(home.path().join("config.yaml")),
            restart_tx,
            proxy_state_store: state_store,
            sniff_cache: Arc::new(crate::sniffer::SniffCache::new()),
        });
        ConnectionManager::new(state)
    }

    #[tokio::test]
    async fn fragmented_quic_routes_by_sni_and_replays_every_packet_in_order() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sink.local_addr().unwrap().port();
        let cm = manager(&format!(
            "hosts: {{quic.example.com: 127.0.0.1}}\nsniffer:\n  enable: true\n  sniff: {{QUIC: {{ports: [{port}]}}}}\nrules: ['IP-CIDR,203.0.113.0/24,REJECT,no-resolve', 'DOMAIN,quic.example.com,DIRECT', 'MATCH,REJECT']\n"
        )).await;
        let mut packets = initial_fragments("quic.example.com");
        packets.reverse(); // UDP fragments can arrive in either order.
        let expected = packets.clone();
        let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let (reply_tx, mut reply_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            cm.handle_udp(
                UdpInbound {
                    src: "127.0.0.1:12345".parse().unwrap(),
                    dst: format!("203.0.113.1:{port}").parse().unwrap(),
                    conn_type: "tun",
                    domain: None,
                },
                rx,
                Duration::from_secs(2),
                |data| {
                    let tx = reply_tx.clone();
                    async move {
                        tx.send(data).await?;
                        Ok(())
                    }
                },
            )
            .await
        });
        for packet in packets {
            tx.send(packet).await.unwrap();
        }
        let mut buf = [0; 2048];
        let mut from = None;
        for packet in expected {
            let (len, peer) = timeout(Duration::from_secs(2), sink.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..len], &packet);
            from = Some(peer);
        }
        sink.send_to(b"response", from.unwrap()).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), reply_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"response"
        );
        // Later client packets use the same routed flow without sniffing.
        tx.send(b"application".to_vec()).await.unwrap();
        let (len, _) = timeout(Duration::from_secs(2), sink.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
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
            let cm = manager(&format!(
                "sniffer:\n  enable: true\n  {policy}\n  sniff: {{QUIC: {{}}}}\nrules: ['DOMAIN,quic.example.com,DIRECT', 'MATCH,REJECT']\n"
            )).await;
            let (tx, rx) = mpsc::channel(UDP_QUEUE_SIZE);
            for packet in initial_fragments("quic.example.com") {
                tx.send(packet).await.unwrap();
            }
            let error = cm
                .handle_udp(
                    UdpInbound {
                        src: "127.0.0.1:12345".parse().unwrap(),
                        dst: "203.0.113.1:443".parse().unwrap(),
                        conn_type: "socks5",
                        domain: None,
                    },
                    rx,
                    Duration::from_secs(1),
                    |_| async { Ok(()) },
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().to_lowercase().contains("reject"),
                "{policy}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn incomplete_quic_times_out_and_replays_original_datagram() {
        let (tx, mut rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let first = initial_fragments("quic.example.com").remove(0);
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
        let (tx, mut rx) = mpsc::channel(UDP_QUEUE_SIZE);
        let sniffed = timeout(
            Duration::from_millis(100),
            sniff_packets(b"DNS query".to_vec(), &mut rx),
        )
        .await
        .unwrap();
        assert!(sniffed.host.is_none());
        assert_eq!(sniffed.packets, vec![b"DNS query".to_vec()]);
        let first = initial_fragments("quic.example.com").remove(0);
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
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(vec![3]).await.unwrap();
        drop(tx);
        timeout(
            Duration::from_secs(1),
            relay_packets(
                &outbound,
                &Address::ip("127.0.0.1:443".parse().unwrap()),
                vec![vec![1], vec![2]],
                &mut rx,
                Duration::from_secs(1),
                |_| async { Ok(()) },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(outbound.writes.load(Ordering::SeqCst), 3);
        assert!(outbound.reads.load(Ordering::SeqCst) >= 3);
    }
}
