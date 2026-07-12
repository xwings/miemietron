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

/// Relay buffer pool matching mihomo's sing/bufio sync.Pool pattern.
static RELAY_BUF_POOL: once_cell::sync::Lazy<RelayBufPool> =
    once_cell::sync::Lazy::new(RelayBufPool::new);

struct RelayBufPool {
    pool: parking_lot::Mutex<Vec<Vec<u8>>>,
}

const RELAY_BUF_SIZE: usize = 16 * 1024;

impl RelayBufPool {
    fn new() -> Self {
        Self {
            pool: parking_lot::Mutex::new(Vec::new()),
        }
    }

    fn get(&self) -> Vec<u8> {
        self.pool
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0u8; RELAY_BUF_SIZE])
    }

    fn put(&self, mut buf: Vec<u8>) {
        if buf.capacity() == RELAY_BUF_SIZE {
            buf.clear();
            let mut pool = self.pool.lock();
            if pool.len() < 64 {
                buf.resize(RELAY_BUF_SIZE, 0);
                pool.push(buf);
            }
        }
    }
}

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

/// mihomo compat: map miemietron's internal inbound tag to mihomo's
/// `Type.String()` value (`constant/metadata.go`). This is the vocabulary used
/// for the `/connections` `type` field and for `IN-TYPE` rule matching — so
/// `IN-TYPE,HTTP` / `IN-TYPE,SOCKS5` / `IN-TYPE,REDIR` behave like mihomo.
pub(crate) fn inbound_type_display(conn_type: &'static str) -> &'static str {
    match conn_type {
        // A CONNECT request through the HTTP proxy is still Type HTTP in mihomo;
        // the HTTPS type is reserved for a TLS-terminating listener (out of scope).
        "http-proxy" | "http-connect" => "HTTP",
        "socks5" => "Socks5",
        "socks4" => "Socks4",
        "redir" => "Redir",
        "tproxy" => "TProxy",
        "tun" => "Tun",
        other => other,
    }
}

/// mihomo compat: constant/adapters.go Chain.String() — a connection's chain
/// renders as `last[first]` (e.g. `MyGroup[node]`), or the single element.
fn chain_display(chains: &[String]) -> String {
    match chains.len() {
        0 => String::new(),
        1 => chains[0].clone(),
        n => format!("{}[{}]", chains[n - 1], chains[0]),
    }
}

/// Maximum number of bytes to peek for sniffing (TLS ClientHello / HTTP headers).
const SNIFF_PEEK_SIZE: usize = 1024;

/// mihomo compat: read deadline for the sniff peek (dispatcher.go uses 1s).
/// Bounds server-speaks-first protocols so they can't stall the dial.
const SNIFF_PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Bidirectional relay matching mihomo's N.Relay (sing/bufio.Copy).
/// Conditional flush: only when read < buf size (interactive data).
async fn relay_bidirectional<A, B>(a: A, b: B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let a_to_b = tokio::spawn(async move {
        let mut buf = RELAY_BUF_POOL.get();
        loop {
            let n = match a_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if b_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
            if n < buf.len() && b_write.flush().await.is_err() {
                break;
            }
        }
        let _ = b_write.shutdown().await;
        RELAY_BUF_POOL.put(buf);
    });

    let b_to_a = tokio::spawn(async move {
        let mut buf = RELAY_BUF_POOL.get();
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
        RELAY_BUF_POOL.put(buf);
    });

    let _ = a_to_b.await;
    let _ = b_to_a.await;
}

/// Connection manager — mihomo tunnel/tunnel.go equivalent.
pub struct ConnectionManager {
    app: Arc<AppState>,
    connections: DashMap<Arc<str>, ConnectionInfo>,
    counters: DashMap<Arc<str>, (Arc<AtomicU64>, Arc<AtomicU64>)>,
    relay_handles: DashMap<Arc<str>, tokio::task::AbortHandle>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionInfo {
    #[serde(serialize_with = "ser_arc_str")]
    pub id: Arc<str>,
    pub metadata: ConnectionMetadata,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
}

/// Serialize Arc<str> as a plain string.
fn ser_arc_str<S: serde::Serializer>(val: &Arc<str>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(val)
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

        // mihomo compat: preHandleMetadata + sniffing flow (tunnel.go
        // handleTCPConn + component/sniffer/dispatcher.go).
        // 1. Try FakeIP reverse lookup (preHandleMetadata)
        // 2. If failed AND sniffing gates allow, try sniffing TLS SNI / HTTP Host
        // 3. Only drop if BOTH failed for FakeIP destinations
        let domain_from_inbound = host_override.is_some();
        let mut domain = host_override.or_else(|| dns.reverse_lookup(&dst.ip()));
        let is_fakeip_dst = dns.is_fake_ip(&dst.ip());
        let mut pre_handle_failed = domain.is_none() && is_fakeip_dst;
        // mihomo DNSMode classification: a domain recovered from the ip→host
        // mapping under redir-host is DNSMapping; a fake-ip recovery is
        // DNSFakeIP (never sniffed unless force-domain matches).
        let domain_from_mapping = domain.is_some() && !domain_from_inbound && !is_fakeip_dst;

        let sniff_cfg = config.sniffer.as_ref();
        let sniff_override = sniff_cfg.and_then(|s| s.should_sniff(dst.port()));

        // mihomo compat: check if the existing domain is in the force-domain list.
        // If so, never skip sniffing and never cache failures.
        // Matches mihomo's `forceSniffer := sd.forceSniff(metadata)`.
        let force_sniffer = sniff_cfg
            .map(|s| domain.as_deref().is_some_and(|d| s.is_force_domain(d)))
            .unwrap_or(false);

        // mihomo compat: dispatcher.go shouldOverride — sniffing only runs when
        // (no host && parse-pure-ip), (mapping-recovered && force-dns-mapping),
        // or the existing host matches force-domain. A client-supplied host or
        // a fake-ip-recovered domain is NOT sniffed otherwise.
        let (parse_pure_ip, force_dns_mapping) = sniff_cfg
            .map(|s| (s.parse_pure_ip, s.force_dns_mapping))
            .unwrap_or((true, true));
        let should_override = (domain.is_none() && parse_pure_ip)
            || (domain_from_mapping && force_dns_mapping)
            || force_sniffer;

        // mihomo compat: skip list check — skip sniffing for destinations that
        // have repeatedly failed, unless forced. Matches mihomo's skipList check
        // in TCPSniff: `if count, ok := sd.skipList.Get(dst); ok && count > 5`.
        let sniff_cache = &self.app.sniff_cache;
        let skip_sniff = if !force_sniffer {
            sniff_cache.should_skip(dst)
        } else {
            false
        };

        let mut peek_buf: Vec<u8> = Vec::new();
        // mihomo compat: metadata.SniffHost — recorded for /connections even
        // when override-destination is false.
        let mut sniff_host = String::new();
        // Set when the sniffed host replaces the metadata host — mihomo's
        // replaceDomain also blanks DstIP so rules match the new domain.
        let mut sniff_overrode = false;
        if sniff_override.is_some() && should_override && !skip_sniff {
            use tokio::io::AsyncReadExt;
            let mut tmp = [0u8; SNIFF_PEEK_SIZE];
            // mihomo compat: dispatcher.go sniffDomain — the first peek has a
            // 1s deadline; a timeout means the peer sent nothing (likely a
            // server-speaks-first protocol): cache the failure, log, and CLOSE
            // the connection ("Consider adding skip").
            let first = tokio::time::timeout(
                SNIFF_PEEK_TIMEOUT,
                AsyncReadExt::read(&mut stream, &mut tmp),
            )
            .await;
            let mut verdict = match first {
                Ok(Ok(0)) => sniffer::SniffAttempt::Fail,
                Ok(Ok(n)) => {
                    peek_buf.extend_from_slice(&tmp[..n]);
                    sniffer::sniff_domain_ex(&peek_buf)
                }
                Ok(Err(e)) => {
                    debug!("Sniff peek read failed: {}", e);
                    sniffer::SniffAttempt::Fail
                }
                Err(_) => {
                    sniff_cache.record_failure(dst);
                    tracing::error!(
                        "[Sniffer] [{}] may not have any sent data, Consider adding skip",
                        dst.ip()
                    );
                    return Ok(());
                }
            };

            // mihomo compat: on errNeedAtLeastData, peek again with a fresh 1s
            // deadline until the needed length is buffered, then re-sniff once.
            if let sniffer::SniffAttempt::NeedMore(needed) = verdict {
                let needed = needed.min(5 + 16384 + 256); // TLS record cap
                let deadline = tokio::time::Instant::now() + SNIFF_PEEK_TIMEOUT;
                while peek_buf.len() < needed {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(remaining, AsyncReadExt::read(&mut stream, &mut tmp))
                        .await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => peek_buf.extend_from_slice(&tmp[..n]),
                        _ => break,
                    }
                }
                verdict = match sniffer::sniff_domain_ex(&peek_buf) {
                    sniffer::SniffAttempt::NeedMore(_) => sniffer::SniffAttempt::Fail,
                    v => v,
                };
            }

            match verdict {
                sniffer::SniffAttempt::Found(sniffed) => {
                    // mihomo compat: TCPSniff — IP literals are rejected
                    // (sniffDomain netip.ParseAddr) and the host must pass
                    // domainCanReplace (valid domain name, not skip-domain).
                    let can_replace = sniffed.parse::<std::net::IpAddr>().is_err()
                        && sniffer::is_domain_name(&sniffed)
                        && !sniff_cfg
                            .map(|s| s.is_skip_domain(&sniffed))
                            .unwrap_or(false);
                    if can_replace {
                        sniff_cache.record_success(dst);
                        sniff_host = sniffed.clone();
                        let override_dst = sniff_override.unwrap_or(false);
                        if override_dst {
                            debug!(
                                "[Sniffer] Sniff TCP [{}]-->[{}] success, replace domain [{:?}]-->[{}]",
                                src, dst, domain, sniffed
                            );
                            domain = Some(sniffed);
                            pre_handle_failed = false;
                            sniff_overrode = true;
                        }
                        // mihomo compat: override-destination false only sets
                        // SniffHost — rules keep matching the original
                        // host/IP, so the sniffed name is NOT adopted.
                    } else {
                        debug!("[Sniffer] Skip sni[{}]", sniffed);
                    }
                }
                _ => {
                    if !force_sniffer {
                        sniff_cache.record_failure(dst);
                    }
                    debug!(
                        "[Sniffer] All sniffing sniff failed from [{}] to [{}]",
                        src, dst
                    );
                }
            }
        } else if skip_sniff && sniff_override.is_some() && should_override {
            debug!("[Sniffer] Skip sniffing[{}] due to multiple failures", dst);
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

        // mihomo compat: clear dst_ip when domain is known and IP is a FakeIP
        // or unresolved placeholder (tunnel.go:288-290). preHandleMetadata sets
        // DstIP = netip.Addr{} for FakeIP so IP-CIDR rules don't match the
        // FakeIP range. Same for HTTP proxy 0.0.0.0 placeholder, and for a
        // sniff override (dispatcher.go replaceDomain blanks DstIP).
        let rule_dst_ip = if domain.is_some()
            && (sniff_overrode || dns.is_fake_ip(&dst.ip()) || dst.ip().is_unspecified())
        {
            None
        } else {
            Some(dst.ip())
        };

        let mut rule_meta = RuleMetadata {
            domain: domain.clone(),
            dst_ip: rule_dst_ip,
            src_ip: Some(src.ip()),
            dst_port: dst.port(),
            src_port: src.port(),
            network: "tcp",
            process_name: proc_name.clone(),
            process_path: proc_path.clone(),
            in_port,
            in_type: Some(inbound_type_display(conn_type)),
            ..Default::default()
        };

        // mihomo compat: resolveMetadata — a hosts-mapped domain gets its IP
        // set BEFORE rule matching (tunnel.go:329-332), so IP-CIDR/GEOIP rules
        // match the hosts-mapped address.
        if let Some(ref d) = rule_meta.domain {
            if let Some(host_ip_str) = config.hosts.get(&d.to_lowercase()) {
                if let Ok(ip) = host_ip_str.parse::<std::net::IpAddr>() {
                    if !dns.is_fake_ip(&ip) {
                        rule_meta.dst_ip = Some(ip);
                    }
                }
            }
        }

        // mihomo compat: tunnel.go match() — resolve the host to a real IP on
        // demand when rule evaluation needs it (GEOIP / IP-CIDR / ... without
        // no-resolve) but dst_ip was blanked for FakeIP. Resolution failure
        // falls through to matching with dst_ip=None, exactly like mihomo.
        if mode != "global"
            && mode != "direct"
            && rule_meta.dst_ip.is_none()
            && rule_meta.domain.is_some()
            && rules.needs_ip_resolution(&rule_meta)
        {
            if let Some(host) = rule_meta.domain.clone() {
                if let Ok(ip) = dns.resolve_real_ip(&host).await {
                    rule_meta.dst_ip = Some(ip);
                }
            }
        }

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

        // Resolve the action to an outbound handler. ProxyManager::resolve_action
        // errors if Action::Proxy(name) cannot be resolved — no silent DIRECT
        // fallback. See ARCHITECTURE.md "Scope" and the regression tests in
        // src/proxy/mod.rs.
        let handler = proxies.resolve_action(&action)?;
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

        // Determine the rule string for the connection entry.
        // mihomo compat: the /connections `rule` field uses RuleType.String()
        // display form (e.g. "DomainSuffix", "Match"), not config syntax.
        let rule_str = crate::rules::rule_type_display(&rule_type).to_string();

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
        use rand::Rng;
        use tokio::time::{timeout, Instant};

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

                    // mihomo compat: shouldStopRetry (tunnel.go:698-712) — ONLY
                    // resolver couldn't-find-ip, ip-version, ipv6-disabled and
                    // reject-loopback errors are terminal. Everything else
                    // (including transient DNS-server failures) is retried;
                    // each retry re-resolves.
                    let should_stop = err_str.contains("couldn't find ip")
                        || err_str.contains("IP not found")
                        || err_str.contains("ip version error")
                        || err_str.contains("IPv6 disabled")
                        || err_str.contains("reject loopback connection");

                    if should_stop {
                        last_err = Some(e);
                        break;
                    }

                    if attempt < MAX_RETRIES - 1 {
                        // mihomo compat: slowdown with jitter (slowdown.go, backoff.go)
                        // duration = Random(min, min * factor^attempt), capped at max
                        let max_dur = (backoff_min_ms * backoff_factor.powi(attempt as i32))
                            .min(backoff_max_ms);
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
            id: conn_id.clone(),
            metadata: ConnectionMetadata {
                network: "tcp",
                conn_type: inbound_type_display(conn_type),
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
        self.connections.insert(conn_id.clone(), conn_info);
        self.counters
            .insert(conn_id.clone(), (up_counter.clone(), down_counter.clone()));
        stats.add_connection();

        // mihomo compat: single info log per connection, logMetadata format
        // (tunnel.go:633-650): `match Type(payload) using Group[proxy]`,
        // distinct lines for GLOBAL/DIRECT modes and unmatched connections.
        if let Some(ci) = self.connections.get(&conn_id) {
            let chains_str = chain_display(&ci.chains);
            if mode == "global" {
                info!("[TCP] {} --> {} using GLOBAL", src, target);
            } else if mode == "direct" {
                info!("[TCP] {} --> {} using DIRECT", src, target);
            } else if ci.rule.is_empty() {
                info!(
                    "[TCP] {} --> {} doesn't match any rule using {}",
                    src, target, chains_str
                );
            } else if !ci.rule_payload.is_empty() {
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

        let local_plain = stream;
        let remote_counted = CountingStream::new(remote, up_counter.clone(), down_counter.clone());

        let relay_handle = tokio::spawn(async move {
            relay_bidirectional(local_plain, remote_counted).await;
        });
        self.relay_handles
            .insert(conn_id.clone(), relay_handle.abort_handle());

        // Wait for the relay to complete (normally or via abort from close_connection)
        let _ = relay_handle.await;

        // Flush totals into global stats
        let up = up_counter.load(Ordering::Relaxed);
        let down = down_counter.load(Ordering::Relaxed);
        stats.add_upload(up);
        stats.add_download(down);
        stats.remove_connection();
        self.relay_handles.remove(&conn_id);
        self.counters.remove(&conn_id);
        self.connections.remove(&conn_id);

        Ok(())
    }

    /// Resolve a UDP datagram's destination through the rule engine.
    ///
    /// Returns the `Action` to take and the resolved domain (if any).
    pub async fn resolve_udp_action(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> (Action, Option<String>) {
        let dns = self.app.dns_resolver();
        let rules = self.app.rule_engine();
        let config = self.app.config();

        let mode = {
            let rt = self.app.runtime_config.read();
            rt.mode.clone()
        };

        let domain = dns.reverse_lookup(&dst.ip());

        // mihomo compat: clear FakeIP from dst_ip (same as TCP path)
        let rule_dst_ip = if dns.is_fake_ip(&dst.ip()) {
            None
        } else {
            Some(dst.ip())
        };

        let mut rule_meta = RuleMetadata {
            domain: domain.clone(),
            dst_ip: rule_dst_ip,
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

        // mihomo compat: tunnel.go match() — resolve the host to a real IP on
        // demand when an IP rule (GEOIP / IP-CIDR / ... without no-resolve) is
        // reached but dst_ip was blanked for FakeIP. Same as the TCP path.
        if mode != "global"
            && mode != "direct"
            && rule_meta.dst_ip.is_none()
            && rule_meta.domain.is_some()
            && rules.needs_ip_resolution(&rule_meta)
        {
            if let Some(host) = rule_meta.domain.clone() {
                if let Ok(ip) = dns.resolve_real_ip(&host).await {
                    rule_meta.dst_ip = Some(ip);
                }
            }
        }

        // mihomo compat: global mode routes to proxies["GLOBAL"]
        let proxies = self.app.proxy_manager();
        let (action, rule_type, rule_payload) = if mode == "global" {
            (
                Action::Proxy("GLOBAL".to_string()),
                String::new(),
                String::new(),
            )
        } else if mode == "direct" {
            (Action::Direct, String::new(), String::new())
        } else {
            // mihomo compat: tunnel.go match() — a matched rule whose adapter
            // doesn't support UDP is skipped and evaluation continues with the
            // later rules ("%s UDP is not supported").
            let adapter_udp_ok = |action: &Action| -> bool {
                match action {
                    // DIRECT / REJECT support UDP in mihomo.
                    Action::Direct | Action::Reject | Action::RejectDrop => true,
                    // Unresolvable names are NOT skipped here — resolve_action
                    // reports them loudly downstream (no silent fallback).
                    Action::Proxy(name) => proxies
                        .resolve(name)
                        .map(|h| h.supports_udp())
                        .unwrap_or(true),
                }
            };
            rules.match_rules_detailed_filtered(&rule_meta, Some(&adapter_udp_ok))
        };

        // mihomo compat: UDP sessions get the same one info log per session as
        // TCP (tunnel.go:475 logMetadata) — without it UDP activity is
        // invisible at info level.
        {
            let target_str = domain
                .as_deref()
                .map(|d| format!("{}:{}", d, dst.port()))
                .unwrap_or_else(|| dst.to_string());
            let chain = match &action {
                Action::Direct => "DIRECT".to_string(),
                Action::Reject => "REJECT".to_string(),
                Action::RejectDrop => "REJECT-DROP".to_string(),
                Action::Proxy(name) => {
                    let final_name = proxies
                        .resolve(name)
                        .map(|h| h.name().to_string())
                        .unwrap_or_default();
                    if final_name.is_empty() || final_name == *name {
                        name.clone()
                    } else {
                        format!("{name}[{final_name}]")
                    }
                }
            };
            if mode == "global" {
                info!("[UDP] {} --> {} using GLOBAL", src, target_str);
            } else if mode == "direct" {
                info!("[UDP] {} --> {} using DIRECT", src, target_str);
            } else if rule_type.is_empty() {
                info!(
                    "[UDP] {} --> {} doesn't match any rule using {}",
                    src, target_str, chain
                );
            } else {
                let rule_disp = crate::rules::rule_type_display(&rule_type);
                if rule_payload.is_empty() {
                    info!(
                        "[UDP] {} --> {} match {} using {}",
                        src, target_str, rule_disp, chain
                    );
                } else {
                    info!(
                        "[UDP] {} --> {} match {}({}) using {}",
                        src, target_str, rule_disp, rule_payload, chain
                    );
                }
            }
        }

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
            id: Arc::from("test-id"),
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
                        if w.write_all(&payload_a).await.is_err() {
                            break;
                        }
                    }
                    let _ = w.shutdown().await;
                    // Drain reads
                    let mut sink = vec![0u8; 4096];
                    while let Ok(n) = r.read(&mut sink).await {
                        if n == 0 {
                            break;
                        }
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
                        if w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if w.flush().await.is_err() {
                            break;
                        }
                    }
                    let _ = w.shutdown().await;
                });

                relay_bidirectional(a_server, b_server).await;
                let _ = writer_a.await;
                let _ = echo_b.await;
            }));
        }

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for h in handles {
                h.await.unwrap();
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "200 concurrent relays (8KB each) should complete within 10s"
        );
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
            )
            .await;

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

        assert_eq!(
            received, total_bytes,
            "receiver should get all {total_bytes} bytes"
        );
        assert_eq!(
            up.load(Ordering::Relaxed) as usize,
            total_bytes,
            "upload counter should match {total_bytes} bytes"
        );
    }
}
