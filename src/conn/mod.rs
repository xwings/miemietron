use anyhow::Result;
use dashmap::DashMap;
use pin_project_lite::pin_project;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error, info};

use crate::common::addr::Address;
use crate::rules::{process, Action, RuleMetadata};
use crate::sniffer;
use crate::AppState;

pin_project! {
    pub struct CountingStream<T> {
        #[pin]
        inner: T,
        upload: Arc<AtomicU64>,
        download: Arc<AtomicU64>,
    }
}

impl<T> CountingStream<T> {
    pub fn new(inner: T, upload: Arc<AtomicU64>, download: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            upload,
            download,
        }
    }

}

impl<T: AsyncRead> AsyncRead for CountingStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();
        let result = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.download.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        result
    }
}

impl<T: AsyncWrite> AsyncWrite for CountingStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                this.upload.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pin_project! {
    /// A stream wrapper that replays `prefix` bytes before reading from `inner`.
    ///
    /// Used for sniffing: we read the first N bytes from the client, inspect them
    /// for TLS SNI / HTTP Host, then construct a PeekableStream so the proxy relay
    /// sees the full original byte sequence.
    pub struct PeekableStream<T> {
        prefix: Vec<u8>,
        prefix_pos: usize,
        #[pin]
        inner: T,
    }
}

impl<T> PeekableStream<T> {
    pub fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PeekableStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        // First drain the prefix buffer
        if *this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[*this.prefix_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            *this.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Then delegate to inner stream
        this.inner.poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PeekableStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Maximum number of bytes to peek for sniffing (TLS ClientHello / HTTP headers).
const SNIFF_PEEK_SIZE: usize = 1024;

/// Bidirectional relay matching mihomo's N.Relay (bufio.Copy in Go).
///
/// Uses two spawned tasks for true concurrency. Each direction reads into a
/// buffer and writes all bytes. Flush is only called when the read didn't fill
/// the buffer — meaning we've consumed all currently available data and should
/// push it to the wire for responsiveness (interactive traffic, protocol
/// handshakes). For bulk transfers (video, downloads), reads fill the buffer
/// and we skip the flush, letting write_all push data through directly.
///
/// mihomo's Go implementation uses bufio.Copy which relies on Go's synchronous
/// Write() — data goes out immediately without explicit flush. In Rust's async
/// model, SsStream's poll_write may buffer encrypted ciphertext when the TCP
/// socket would block. The conditional flush handles this: bulk data naturally
/// drains the buffer via continuous write_all calls, while small interactive
/// data gets an explicit flush to prevent deadlocks.
async fn relay_bidirectional<A, B>(a: A, b: B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let a_to_b = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match a_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if b_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
            // Only flush when read returned less than buffer size — we've
            // drained available data and should push it out for responsiveness.
            // For bulk transfers (video), reads fill the buffer and we skip
            // flush, avoiding the overhead of ~1500 extra syscalls/sec at 50Mbps.
            if n < buf.len() && b_write.flush().await.is_err() {
                break;
            }
        }
        let _ = b_write.shutdown().await;
    });

    let b_to_a = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match b_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if a_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
            if n < buf.len() && a_write.flush().await.is_err() {
                break;
            }
        }
        let _ = a_write.shutdown().await;
    });

    let _ = a_to_b.await;
    let _ = b_to_a.await;
}

/// Manages active connections and orchestrates the proxy pipeline.
///
/// Reads from the shared `AppState` on each new connection, so hot-reloaded
/// configs, rules, proxies, and DNS are picked up immediately for new
/// connections while existing connections continue with their snapshotted state.
pub struct ConnectionManager {
    app: Arc<AppState>,
    connections: DashMap<String, ConnectionInfo>,
    /// Live byte counters per connection ID, so the API can read real-time
    /// upload/download values instead of the stale zeros stored at insert time.
    counters: DashMap<String, (Arc<AtomicU64>, Arc<AtomicU64>)>,
    /// Abort handles for relay tasks, so close_connection() can actually
    /// terminate the relay and close the underlying streams.
    relay_handles: DashMap<String, tokio::task::AbortHandle>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub metadata: ConnectionMetadata,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
}

/// Serialize IpAddr as string without intermediate String allocation.
fn ser_ip<S: serde::Serializer>(ip: &std::net::IpAddr, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(ip)
}

/// Serialize u16 as string without intermediate String allocation.
fn ser_port_str<S: serde::Serializer>(port: &u16, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(port)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionMetadata {
    pub network: &'static str,
    #[serde(rename = "type")]
    pub conn_type: &'static str,
    #[serde(rename = "sourceIP", serialize_with = "ser_ip")]
    pub source_ip: std::net::IpAddr,
    #[serde(rename = "destinationIP", serialize_with = "ser_ip")]
    pub destination_ip: std::net::IpAddr,
    #[serde(rename = "sourcePort", serialize_with = "ser_port_str")]
    pub source_port: u16,
    #[serde(rename = "destinationPort", serialize_with = "ser_port_str")]
    pub destination_port: u16,
    pub host: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: &'static str,
    #[serde(rename = "processPath")]
    pub process_path: String,
    #[serde(rename = "specialProxy")]
    pub special_proxy: &'static str,
    #[serde(rename = "specialRules")]
    pub special_rules: &'static str,
    #[serde(rename = "remoteDestination")]
    pub remote_destination: String,
    pub dscp: u8,
    #[serde(rename = "sniffHost")]
    pub sniff_host: String,
}

impl ConnectionManager {
    pub fn new(app: Arc<AppState>) -> Self {
        Self {
            app,
            connections: DashMap::new(),
            counters: DashMap::new(),
            relay_handles: DashMap::new(),
        }
    }

    /// Handle a new TCP connection from the TUN stack.
    pub async fn handle_tcp(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    ) -> Result<()> {
        self.handle_tcp_typed(src, dst, stream, "tun").await
    }

    /// Handle a TCP connection with an explicit host override (for HTTP/SOCKS
    /// proxies where the domain is already known from the request).
    pub async fn handle_tcp_with_host(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        conn_type: &'static str,
        host_override: Option<String>,
    ) -> Result<()> {
        self.handle_tcp_inner(src, dst, stream, conn_type, host_override)
            .await
    }

    /// Inner implementation that also accepts a connection-type tag (e.g. "tun",
    /// "http-proxy", "socks5").
    pub async fn handle_tcp_typed(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        conn_type: &'static str,
    ) -> Result<()> {
        self.handle_tcp_inner(src, dst, stream, conn_type, None)
            .await
    }

    async fn handle_tcp_inner(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        conn_type: &'static str,
        host_override: Option<String>,
    ) -> Result<()> {
        // mihomo compat: fixMetadata — unmap IPv4-mapped IPv6 addresses.
        // Matches mihomo's `metadata.DstIP = metadata.DstIP.Unmap()`.
        let dst = match dst.ip() {
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    SocketAddr::new(std::net::IpAddr::V4(v4), dst.port())
                } else {
                    dst
                }
            }
            _ => dst,
        };

        // Snapshot current state from AppState (cheap Arc clones).
        // Existing connections keep their snapshot; new connections get the latest.
        let dns = self.app.dns_resolver();
        let rules = self.app.rule_engine();
        let proxies = self.app.proxy_manager();
        let config = self.app.config();
        let stats = &self.app.stats;

        // Read current mode from runtime config
        let mode = {
            let rt = self.app.runtime_config.read();
            rt.mode.clone()
        };

        // mihomo compat: preHandleMetadata + sniffing flow.
        // 1. Try FakeIP reverse lookup (preHandleMetadata)
        // 2. If failed AND sniffing enabled, try sniffing TLS SNI / HTTP Host
        // 3. Only drop if BOTH failed for FakeIP destinations
        let mut domain = host_override.or_else(|| dns.reverse_lookup(&dst.ip()));
        let mut pre_handle_failed = domain.is_none() && dns.is_fake_ip(&dst.ip());

        let sniff_cfg = config.sniffer.as_ref();
        let sniff_override = sniff_cfg.and_then(|s| s.should_sniff(dst.port()));

        // mihomo compat: check if the existing domain is in the force-domain list.
        // If so, never skip sniffing and never cache failures.
        // Matches mihomo's `forceSniffer := sd.forceSniff(metadata)`.
        let force_sniffer = sniff_cfg
            .map(|s| domain.as_deref().is_some_and(|d| s.is_force_domain(d)))
            .unwrap_or(false);

        // mihomo compat: skip list check — skip sniffing for destinations that
        // have repeatedly failed, unless forced. Matches mihomo's skipList check
        // in TCPSniff: `if count, ok := sd.skipList.Get(dst); ok && count > 5`.
        let sniff_cache = &self.app.sniff_cache;
        let skip_sniff = if !force_sniffer {
            sniff_cache.should_skip(dst)
        } else {
            false
        };

        let mut peek_arr = [0u8; SNIFF_PEEK_SIZE]; // stack, not heap
        let peeked_len = if sniff_override.is_some() && !skip_sniff {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut peek_arr).await {
                Ok(n) => n,
                Err(e) => {
                    debug!("Sniff peek read failed: {}", e);
                    0
                }
            }
        } else {
            if skip_sniff && sniff_override.is_some() {
                debug!("[Sniffer] Skip sniffing[{}] due to multiple failures", dst);
            }
            0
        };
        // Only heap-allocate the actual peeked bytes (not the full 1KB buffer)
        let peek_buf = peek_arr[..peeked_len].to_vec();

        let mut sniff_host = String::new();
        let mut sniff_succeeded = false;
        if peeked_len > 0 {
            if let Some(sniffed) = sniffer::sniff_domain(&peek_buf) {
                sniff_host = sniffed.clone();
                sniff_succeeded = true;

                let sniffer = sniff_cfg.unwrap();
                let override_dst = sniff_override.unwrap_or(false);

                let should_override = if sniffer.is_force_domain(&sniffed) {
                    true
                } else if sniffer.is_skip_domain(&sniffed) {
                    false
                } else {
                    override_dst
                };

                if domain.is_none() {
                    domain = Some(sniffed);
                    pre_handle_failed = false; // Sniffing recovered the domain
                } else if should_override {
                    domain = Some(sniffed);
                }
            }
        }

        // mihomo compat: update skip list based on sniff result.
        // On success: delete from skip list (`sd.skipList.Delete(dst)`).
        // On failure: increment failure counter (`sd.cacheSniffFailed(metadata)`).
        if sniff_override.is_some() && !skip_sniff {
            if sniff_succeeded {
                sniff_cache.record_success(dst);
            } else if peeked_len > 0 && !force_sniffer {
                sniff_cache.record_failure(dst);
            }
        }

        // mihomo compat: only drop if preHandle failed AND sniffing didn't recover
        if pre_handle_failed {
            debug!("fake DNS record {} missing, sniffing failed", dst.ip());
            return Ok(());
        }

        // Wrap the stream so the peeked bytes are replayed before the rest
        let stream = PeekableStream::new(peek_buf, stream);

        // Build the target address. Domain takes priority (always set for
        // FakeIP connections thanks to the early check above). For non-FakeIP
        // traffic without a domain (raw IP connections), use the IP directly.
        let target = if let Some(ref domain) = domain {
            Address::domain(domain, dst.port())
        } else {
            Address::ip(dst)
        };

        // Process detection: look up the process that owns this source socket.
        // Only do this if find-process-mode is not "off" (default is to detect).
        // mihomo compat: default to FindProcessStrict — defers process lookup
        // until a PROCESS-NAME/PROCESS-PATH rule actually needs it.
        let find_process_mode = config.find_process_mode.as_deref().unwrap_or("strict");
        let (proc_name, proc_path) = if find_process_mode != "off" {
            // Wrap in a timeout to avoid blocking on slow /proc scans
            let src_ip = src.ip();
            let src_p = src.port();
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                tokio::task::spawn_blocking(move || process::lookup_process(&src_ip, src_p)),
            )
            .await
            {
                Ok(Ok(Some((name, path)))) => (Some(name), Some(path)),
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        // Determine inbound listener port from connection type and config
        let in_port = match conn_type {
            "http-proxy" | "http-connect" => Some(config.port),
            "socks5" => Some(config.socks_port),
            "tun" | "redir" => Some(config.redir_port),
            "tproxy" => Some(config.tproxy_port),
            _ => {
                if config.mixed_port > 0 {
                    Some(config.mixed_port)
                } else {
                    None
                }
            }
        };

        // Build rule metadata
        let rule_meta = RuleMetadata {
            domain: domain.clone(),
            dst_ip: Some(dst.ip()),
            src_ip: Some(src.ip()),
            dst_port: dst.port(),
            src_port: src.port(),
            network: "tcp",
            process_name: proc_name.clone(),
            process_path: proc_path.clone(),
            in_port,
            in_type: Some(conn_type),
            ..Default::default()
        };

        // Match rules
        // mihomo compat: global mode routes to proxies["GLOBAL"], direct mode to DIRECT
        let (action, rule_type, rule_payload) = if mode == "global" {
            (
                Action::Proxy("GLOBAL".to_string()),
                "MATCH".to_string(),
                String::new(),
            )
        } else if mode == "direct" {
            (Action::Direct, "DIRECT".to_string(), String::new())
        } else {
            rules.match_rules_detailed(&rule_meta)
        };

        debug!(
            "TCP {} -> {} ({}) => {:?} [{}]",
            src,
            target,
            domain.as_deref().unwrap_or(""),
            action,
            rule_type
        );

        // Get the group name (if routed through a proxy group) for chains
        let group_name = match &action {
            Action::Proxy(name) => Some(name.clone()),
            _ => None,
        };

        // mihomo compat: Touch the group to mark it as recently used (for lazy health checks).
        // Matches mihomo's GroupBase.GetProxies(touch=true) pattern.
        let group_arc = group_name.as_ref().and_then(|gn| proxies.get_group(gn));
        if let Some(ref group) = group_arc {
            group.touch();
        }

        // Get outbound handler
        let handler = match &action {
            Action::Direct => proxies.get("DIRECT"),
            Action::Reject => proxies.get("REJECT"),
            Action::RejectDrop => proxies.get("REJECT-DROP"),
            Action::Proxy(name) => proxies.resolve(name),
        };

        let handler = match handler.or_else(|| proxies.get("DIRECT")) {
            Some(h) => h,
            None => return Err(anyhow::anyhow!("no proxy handler found and DIRECT missing")),
        };
        let proxy_name = handler.name().to_string();
        let proxy_proto = handler.proto().to_string();

        // Build chains: [final_proxy, group_name] (mihomo convention: innermost first)
        let chains = if let Some(ref gn) = group_name {
            if gn != &proxy_name {
                vec![proxy_name.clone(), gn.clone()]
            } else {
                vec![proxy_name.clone()]
            }
        } else {
            vec![proxy_name.clone()]
        };

        // Determine the rule string for the connection entry
        let rule_str = rule_type;

        // mihomo compat: check hosts map for domain overrides before dialing.
        // Matches mihomo's resolveMetadata: if host is in DefaultHosts and the
        // resolved IP is not a FakeIP, override DstIP (domain preserved for SNI).
        let target = if let Some(ref domain) = domain {
            if let Some(host_ip_str) = config.hosts.get(&domain.to_lowercase()) {
                if let Ok(ip) = host_ip_str.parse::<std::net::IpAddr>() {
                    if !dns.is_fake_ip(&ip) {
                        debug!("Hosts override: {} -> {}", domain, ip);
                        // Use domain target so SNI is preserved, but the adapter
                        // will resolve the domain to this IP via the DNS resolver.
                        // For DIRECT connections, override to the IP target directly.
                        Address::ip(SocketAddr::new(ip, dst.port()))
                    } else {
                        target
                    }
                } else {
                    target
                }
            } else {
                target
            }
        } else {
            target
        };

        // mihomo compat: retry() with context timeout (tunnel.go:554-591, 695-716).
        // Entire retry loop bounded by DefaultTCPTimeout (5s).
        // Max 10 iterations but the context timeout is the real limit.
        // Backoff uses jitter: duration = Random(min, min * factor^attempt)
        // via slowdown.New() (slowdown.go, backoff.go).
        debug!(
            "Connecting via [{}] {} to {}",
            handler.proto(),
            proxy_name,
            target
        );
        use tokio::time::{timeout, Instant};
        use rand::Rng;

        let retry_deadline = Instant::now() + std::time::Duration::from_secs(5); // C.DefaultTCPTimeout
        const MAX_RETRIES: usize = 10;
        let mut last_err = None;
        let mut remote_conn = None;
        let backoff_min_ms: f64 = 10.0;
        let backoff_factor: f64 = 2.0;
        let backoff_max_ms: f64 = 1000.0;

        for attempt in 0..MAX_RETRIES {
            // Check if we've exceeded the overall timeout
            let remaining = retry_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Dial with remaining time as timeout
            match timeout(remaining, handler.connect_stream(&target, &dns)).await {
                Ok(Ok(r)) => {
                    // mihomo compat: notify group of successful dial
                    if let Some(ref group) = group_arc {
                        group.on_dial_success();
                    }
                    remote_conn = Some(r);
                    break;
                }
                Ok(Err(e)) => {
                    let err_str = e.to_string();

                    // mihomo compat: shouldStopRetry (tunnel.go:679-693)
                    let should_stop = err_str.contains("IP not found")
                        || err_str.contains("IPv6 disabled")
                        || err_str.contains("loopback")
                        || err_str.contains("connection rejected")
                        || err_str.contains("all DNS servers failed")
                        || err_str.contains("cached negative result");

                    if should_stop {
                        last_err = Some(e);
                        break;
                    }

                    if attempt < MAX_RETRIES - 1 {
                        // mihomo compat: slowdown with jitter (slowdown.go, backoff.go)
                        // duration = Random(min, min * factor^attempt), capped at max
                        let max_dur = (backoff_min_ms * backoff_factor.powi(attempt as i32)).min(backoff_max_ms);
                        let jittered = rand::thread_rng().gen_range(backoff_min_ms..=max_dur);
                        let sleep_dur = std::time::Duration::from_millis(jittered as u64);

                        debug!(
                            "Proxy connect attempt {}/{} failed [{}] {} -> {}: {}, retrying in {}ms",
                            attempt + 1,
                            MAX_RETRIES,
                            proxy_name,
                            src,
                            target,
                            e,
                            jittered as u64
                        );

                        // Context-aware sleep: don't sleep past deadline
                        let remaining = retry_deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            last_err = Some(e);
                            break;
                        }
                        tokio::time::sleep(sleep_dur.min(remaining)).await;
                    }
                    last_err = Some(e);
                }
                Err(_timeout) => {
                    // Overall timeout expired during dial
                    last_err = Some(anyhow::anyhow!("connect timeout"));
                    break;
                }
            }
        }

        let remote = match remote_conn {
            Some(r) => r,
            None => {
                let e = last_err.unwrap();
                error!(
                    "Proxy connect failed after {} attempts [{}] {} -> {}: {}",
                    MAX_RETRIES, proxy_name, src, target, e
                );
                // mihomo compat: notify group of failed dial
                // This may trigger an immediate health check after repeated failures.
                if let Some(ref group) = group_arc {
                    group.on_dial_failed(&proxy_proto, &e.to_string());
                }
                return Err(e);
            }
        };

        let conn_id: Arc<str> = uuid::Uuid::new_v4().to_string().into();
        let up_counter = Arc::new(AtomicU64::new(0));
        let down_counter = Arc::new(AtomicU64::new(0));

        // Register connection in the DashMap
        let conn_info = ConnectionInfo {
            id: conn_id.to_string(),
            metadata: ConnectionMetadata {
                network: "tcp",
                conn_type,
                source_ip: src.ip(),
                destination_ip: dst.ip(),
                source_port: src.port(),
                destination_port: dst.port(),
                host: domain.clone().unwrap_or_default(),
                dns_mode: if domain.is_some() { "fake-ip" } else { "" },
                process_path: proc_path.unwrap_or_default(),
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
            rule: rule_str,
            rule_payload,
        };
        let conn_id_str = conn_id.to_string();
        self.connections.insert(conn_id_str.clone(), conn_info);
        // Store live counters so the API can read real-time byte counts
        self.counters
            .insert(conn_id_str.clone(), (up_counter.clone(), down_counter.clone()));
        stats.add_connection();

        // mihomo compat: single info log per connection after successful dial.
        // Format matches mihomo tunnel.go line 617-629.
        if let Some(ci) = self.connections.get(&conn_id_str) {
            let chains_str = format!("{:?}", ci.chains);
            if !ci.rule_payload.is_empty() {
                info!(
                    "[TCP] {} --> {} match {}({}) using {}",
                    src, target, ci.rule, ci.rule_payload, chains_str
                );
            } else {
                info!(
                    "[TCP] {} --> {} match {} using {}",
                    src, target, ci.rule, chains_str
                );
            }
        }

        // Wrap only the remote side with CountingStream to avoid double-counting
        let local_plain = stream;
        let remote_counted = CountingStream::new(remote, up_counter.clone(), down_counter.clone());

        // mihomo compat: bidirectional relay matching Go's goroutine-based N.Relay.
        // Go's Write blocks until ALL bytes are committed. Rust's poll_write can
        // buffer data internally (e.g., SsStream encrypts then partially writes).
        // tokio::io::copy doesn't flush between writes, causing deadlocks.
        // Solution: custom relay that flushes after each write cycle.
        //
        // Spawn the relay as a task so close_connection() can abort it.
        // When aborted, the underlying streams are dropped (closing the connection).
        let relay_handle = tokio::spawn(async move {
            relay_bidirectional(local_plain, remote_counted).await;
        });
        self.relay_handles
            .insert(conn_id_str.clone(), relay_handle.abort_handle());

        // Wait for the relay to complete (normally or via abort from close_connection)
        let _ = relay_handle.await;

        // Flush totals into global stats
        let up = up_counter.load(Ordering::Relaxed);
        let down = down_counter.load(Ordering::Relaxed);
        stats.add_upload(up);
        stats.add_download(down);
        stats.remove_connection();
        self.relay_handles.remove(&*conn_id);
        self.counters.remove(&*conn_id);
        self.connections.remove(&*conn_id);

        Ok(())
    }

    /// Resolve a UDP datagram's destination through the rule engine.
    ///
    /// Returns the `Action` to take and the resolved domain (if any).
    pub fn resolve_udp_action(&self, src: SocketAddr, dst: SocketAddr) -> (Action, Option<String>) {
        let dns = self.app.dns_resolver();
        let rules = self.app.rule_engine();
        let config = self.app.config();

        let mode = {
            let rt = self.app.runtime_config.read();
            rt.mode.clone()
        };

        // Resolve domain from FakeIP
        let domain = dns.reverse_lookup(&dst.ip());

        // Build rule metadata
        let rule_meta = RuleMetadata {
            domain: domain.clone(),
            dst_ip: Some(dst.ip()),
            src_ip: Some(src.ip()),
            dst_port: dst.port(),
            src_port: src.port(),
            network: "udp",
            process_name: None,
            process_path: None,
            in_port: Some(config.tproxy_port),
            in_type: Some("tproxy"),
            ..Default::default()
        };

        // mihomo compat: global mode routes to proxies["GLOBAL"]
        let action = if mode == "global" {
            Action::Proxy("GLOBAL".to_string())
        } else if mode == "direct" {
            Action::Direct
        } else {
            rules.match_rules(&rule_meta)
        };

        (action, domain)
    }

    /// Get the current proxy manager (for resolving proxy names to handlers).
    pub fn proxy_manager(&self) -> Arc<crate::proxy::ProxyManager> {
        self.app.proxy_manager()
    }

    /// Get the current DNS resolver.
    pub fn dns_resolver(&self) -> Arc<crate::dns::DnsResolver> {
        self.app.dns_resolver()
    }

    /// Get a snapshot of all active connections (for API).
    /// Reads live byte counters so upload/download values reflect real-time traffic.
    pub fn snapshot(&self) -> ConnectionSnapshot {
        let connections: Vec<ConnectionInfo> = self
            .connections
            .iter()
            .map(|entry| {
                let mut info = entry.value().clone();
                // Read live counter values instead of the stale zeros stored at insert time
                if let Some(counters) = self.counters.get(&info.id) {
                    let (up, down) = counters.value();
                    info.upload = up.load(Ordering::Relaxed);
                    info.download = down.load(Ordering::Relaxed);
                }
                info
            })
            .collect();

        ConnectionSnapshot {
            download_total: self.app.stats.download_total(),
            upload_total: self.app.stats.upload_total(),
            connections,
            memory: get_memory_usage(),
        }
    }

    /// Close all active connections by aborting their relay tasks.
    /// When aborted, the spawned relay task is cancelled and the underlying
    /// streams are dropped, closing the TCP connections.
    pub fn close_all(&self) {
        for entry in self.relay_handles.iter() {
            entry.value().abort();
        }
        self.relay_handles.clear();
        self.counters.clear();
        self.connections.clear();
    }

    /// Close a specific connection by ID, aborting its relay task.
    pub fn close_connection(&self, id: &str) -> bool {
        if let Some((_, handle)) = self.relay_handles.remove(id) {
            handle.abort();
        }
        self.counters.remove(id);
        self.connections.remove(id).is_some()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionSnapshot {
    #[serde(rename = "downloadTotal")]
    pub download_total: u64,
    #[serde(rename = "uploadTotal")]
    pub upload_total: u64,
    pub connections: Vec<ConnectionInfo>,
    pub memory: u64,
}

/// Global traffic and connection statistics.
#[derive(Default)]
pub struct StatsManager {
    upload_total: AtomicU64,
    download_total: AtomicU64,
    active_connections: AtomicU64,
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }

    pub fn add_upload(&self, bytes: u64) {
        self.upload_total.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download_total.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn upload_total(&self) -> u64 {
        self.upload_total.load(Ordering::Relaxed)
    }

    pub fn download_total(&self) -> u64 {
        self.download_total.load(Ordering::Relaxed)
    }

    pub fn add_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remove_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }
}

fn get_memory_usage() -> u64 {
    // Read /proc/self/statm for RSS
    if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pages) = parts[1].parse::<u64>() {
                return pages * 4096; // page size
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn peekable_stream_replays_prefix_then_inner() {
        let prefix = b"hello".to_vec();
        let inner_data = b"world";
        let inner = tokio_test::io::Builder::new().read(inner_data).build();
        let mut stream = PeekableStream::new(prefix, inner);

        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn peekable_stream_partial_prefix_read() {
        let prefix = b"abcdef".to_vec();
        let inner = tokio_test::io::Builder::new().build();
        let mut stream = PeekableStream::new(prefix, inner);

        // Read only 3 bytes at a time
        let mut buf = vec![0u8; 3];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abc");

        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"def");
    }

    #[tokio::test]
    async fn peekable_stream_empty_prefix() {
        let inner_data = b"data";
        let inner = tokio_test::io::Builder::new().read(inner_data).build();
        let mut stream = PeekableStream::new(vec![], inner);

        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"data");
    }

    #[tokio::test]
    async fn counting_stream_tracks_download_bytes() {
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let inner = tokio_test::io::Builder::new().read(b"hello world").build();
        let mut stream = CountingStream::new(inner, up.clone(), down.clone());

        let mut buf = vec![0u8; 20];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 11);
        assert_eq!(down.load(Ordering::Relaxed), 11);
        assert_eq!(up.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn counting_stream_tracks_upload_bytes() {
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let inner = tokio_test::io::Builder::new().write(b"outgoing").build();
        let mut stream = CountingStream::new(inner, up.clone(), down.clone());

        let n = stream.write(b"outgoing").await.unwrap();
        assert_eq!(n, 8);
        assert_eq!(up.load(Ordering::Relaxed), 8);
        assert_eq!(down.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn counting_stream_accumulates_multiple_ops() {
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let inner = tokio_test::io::Builder::new()
            .read(b"abc")
            .read(b"defgh")
            .write(b"12")
            .write(b"3456")
            .build();
        let mut stream = CountingStream::new(inner, up.clone(), down.clone());

        let mut buf = vec![0u8; 10];
        stream.read(&mut buf).await.unwrap();
        stream.read(&mut buf).await.unwrap();
        stream.write(b"12").await.unwrap();
        stream.write(b"3456").await.unwrap();

        assert_eq!(down.load(Ordering::Relaxed), 8); // 3 + 5
        assert_eq!(up.load(Ordering::Relaxed), 6); // 2 + 4
    }

    #[test]
    fn connection_info_serializes_correctly() {
        let info = ConnectionInfo {
            id: "test-id".to_string(),
            metadata: ConnectionMetadata {
                network: "tcp",
                conn_type: "tun",
                source_ip: "192.168.1.1".parse().unwrap(),
                destination_ip: "1.2.3.4".parse().unwrap(),
                source_port: 12345,
                destination_port: 443,
                host: "example.com".to_string(),
                dns_mode: "fake-ip",
                process_path: "".to_string(),
                special_proxy: "",
                special_rules: "",
                remote_destination: "example.com:443".to_string(),
                dscp: 0,
                sniff_host: "example.com".to_string(),
            },
            upload: 100,
            download: 200,
            start: "2024-01-01T00:00:00Z".to_string(),
            chains: vec!["proxy-a".to_string(), "Group".to_string()],
            rule: "DOMAIN-SUFFIX".to_string(),
            rule_payload: "example.com".to_string(),
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["id"], "test-id");
        assert_eq!(json["metadata"]["network"], "tcp");
        assert_eq!(json["metadata"]["type"], "tun");
        assert_eq!(json["metadata"]["sourceIP"], "192.168.1.1");
        assert_eq!(json["metadata"]["destinationIP"], "1.2.3.4");
        assert_eq!(json["metadata"]["sourcePort"], "12345");
        assert_eq!(json["metadata"]["destinationPort"], "443");
        assert_eq!(json["metadata"]["host"], "example.com");
        assert_eq!(json["metadata"]["dnsMode"], "fake-ip");
        assert_eq!(json["metadata"]["processPath"], "");
        assert_eq!(json["metadata"]["specialProxy"], "");
        assert_eq!(json["metadata"]["specialRules"], "");
        assert_eq!(json["metadata"]["remoteDestination"], "example.com:443");
        assert_eq!(json["metadata"]["dscp"], 0);
        assert_eq!(json["metadata"]["sniffHost"], "example.com");
        assert_eq!(json["upload"], 100);
        assert_eq!(json["download"], 200);
        assert_eq!(json["rulePayload"], "example.com");
    }

    #[test]
    fn connection_snapshot_serializes_with_renamed_fields() {
        let snap = ConnectionSnapshot {
            download_total: 1000,
            upload_total: 500,
            connections: vec![],
            memory: 4096,
        };

        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["downloadTotal"], 1000);
        assert_eq!(json["uploadTotal"], 500);
        assert!(json["connections"].as_array().unwrap().is_empty());
        assert_eq!(json["memory"], 4096);
    }

    #[test]
    fn stats_manager_tracks_traffic() {
        let stats = StatsManager::new();
        stats.add_upload(100);
        stats.add_upload(50);
        stats.add_download(200);
        assert_eq!(stats.upload_total(), 150);
        assert_eq!(stats.download_total(), 200);
    }

    #[test]
    fn stats_manager_tracks_connections() {
        let stats = StatsManager::new();
        assert_eq!(stats.active_connections(), 0);
        stats.add_connection();
        stats.add_connection();
        assert_eq!(stats.active_connections(), 2);
        stats.remove_connection();
        assert_eq!(stats.active_connections(), 1);
    }

    /// Stress test: 200 concurrent bidirectional relays.
    ///
    /// Each relay transfers 8KB of data both directions simultaneously.
    /// Verifies all relays complete, no task leaks, no deadlocks.
    /// This simulates a busy router with many active TCP connections.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_relay_200_concurrent() {
        let num_relays = 200;
        let chunk_size = 1024;
        let chunks_per_direction = 8; // 8KB total per direction

        let mut handles = Vec::new();

        for i in 0..num_relays {
            handles.push(tokio::spawn(async move {
                let (a_client, a_server) = tokio::io::duplex(8192);
                let (b_client, b_server) = tokio::io::duplex(8192);

                let payload: Vec<u8> = (0..chunk_size).map(|j| ((i + j) % 256) as u8).collect();

                // Side A: send chunks then close write side
                let payload_a = payload.clone();
                let writer_a = tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(a_client);
                    for _ in 0..chunks_per_direction {
                        if w.write_all(&payload_a).await.is_err() { break; }
                    }
                    let _ = w.shutdown().await;
                    // Drain reads
                    let mut sink = vec![0u8; 4096];
                    while let Ok(n) = r.read(&mut sink).await {
                        if n == 0 { break; }
                    }
                });

                // Side B: echo everything back then close
                let echo_b = tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(b_client);
                    let mut buf = vec![0u8; 4096];
                    loop {
                        let n = match r.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(_) => break,
                        };
                        if w.write_all(&buf[..n]).await.is_err() { break; }
                        if w.flush().await.is_err() { break; }
                    }
                    let _ = w.shutdown().await;
                });

                relay_bidirectional(a_server, b_server).await;
                let _ = writer_a.await;
                let _ = echo_b.await;
            }));
        }

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                for h in handles {
                    h.await.unwrap();
                }
            }
        ).await;

        assert!(result.is_ok(), "200 concurrent relays (8KB each) should complete within 10s");
    }

    /// Stress test: relay with one side that drops immediately.
    ///
    /// Simulates connection reset / client disconnect — the relay must
    /// clean up both directions without hanging.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stress_relay_abrupt_close() {
        for _ in 0..200 {
            let (a_client, a_server) = tokio::io::duplex(4096);
            let (b_client, b_server) = tokio::io::duplex(4096);

            // Drop side A immediately — simulates client disconnect
            drop(a_client);
            // Drop side B immediately — simulates server disconnect
            drop(b_client);

            // Relay should detect both sides closed and return quickly
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                relay_bidirectional(a_server, b_server),
            ).await;

            assert!(result.is_ok(), "relay should handle abrupt close within 1s");
        }
    }

    /// Stress test: counting stream accuracy under high throughput.
    ///
    /// Sends 10MB through a CountingStream and verifies byte counts match exactly.
    #[tokio::test]
    async fn stress_counting_stream_accuracy() {
        let total_bytes: usize = 10 * 1024 * 1024; // 10MB
        let chunk_size = 8192;
        let num_chunks = total_bytes / chunk_size;

        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));

        // Create a duplex where we write through CountingStream and read from the other end
        let (client, server) = tokio::io::duplex(65536);
        let mut counted = CountingStream::new(client, up.clone(), down.clone());

        let reader = tokio::spawn(async move {
            let mut server = server;
            let mut total = 0usize;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = match server.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                total += n;
            }
            total
        });

        // Write 10MB in chunks
        let data = vec![0xABu8; chunk_size];
        for _ in 0..num_chunks {
            counted.write_all(&data).await.unwrap();
        }
        counted.shutdown().await.unwrap();

        let received = reader.await.unwrap();

        assert_eq!(received, total_bytes, "receiver should get all {total_bytes} bytes");
        assert_eq!(
            up.load(Ordering::Relaxed) as usize,
            total_bytes,
            "upload counter should match {total_bytes} bytes"
        );
    }
}
