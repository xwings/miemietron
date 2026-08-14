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

    fn put(&self, buf: Vec<u8>) {
        // Buffers keep len == RELAY_BUF_SIZE for their whole lifetime (read()
        // never shrinks a Vec), so no re-zeroing or resize is needed.
        if buf.capacity() == RELAY_BUF_SIZE {
            debug_assert_eq!(buf.len(), RELAY_BUF_SIZE);
            let mut pool = self.pool.lock();
            if pool.len() < 64 {
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
            if *this.prefix_pos == this.prefix.len() {
                // Fully drained — free the prefix allocation instead of
                // keeping it around for the connection's lifetime.
                *this.prefix = Vec::new();
                *this.prefix_pos = 0;
            }
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

/// Inbound listener port for a connection type (mihomo metadata.InPort),
/// used for IN-PORT rule matching. Shared by the TCP and UDP paths.
fn inbound_port(config: &crate::config::MiemieConfig, conn_type: &str) -> Option<u16> {
    match conn_type {
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
    }
}

/// mihomo compat: tunnel.go match() — resolve the host to a real IP on
/// demand when rule evaluation needs it (GEOIP / IP-CIDR / ... without
/// no-resolve) but dst_ip was blanked for FakeIP. Resolution failure
/// falls through to matching with dst_ip=None, exactly like mihomo.
async fn resolve_ip_on_demand(
    mode: &str,
    rule_meta: &mut RuleMetadata,
    rules: &crate::rules::RuleEngine,
    dns: &crate::dns::DnsResolver,
) {
    if mode != "global"
        && mode != "direct"
        && rule_meta.dst_ip.is_none()
        && rule_meta.domain.is_some()
        && rules.needs_ip_resolution(rule_meta)
    {
        if let Some(host) = rule_meta.domain.clone() {
            if let Ok(ip) = dns.resolve_real_ip(&host).await {
                rule_meta.dst_ip = Some(ip);
            }
        }
    }
}

/// mihomo compat: tunnel.go retry() with a context timeout (tunnel.go:554-591,
/// 695-716). The whole loop is bounded by DefaultTCPTimeout (5s); the 10-attempt
/// cap is a backstop, the deadline is the real limit. Backoff is jittered —
/// `duration = Random(min, min * factor^attempt)` via slowdown.New().
async fn dial_with_retry(
    handler: &Arc<dyn crate::proxy::OutboundHandler>,
    group: Option<&Arc<dyn crate::proxy_group::ProxyGroup>>,
    target: &Address,
    dns: &crate::dns::DnsResolver,
    src: SocketAddr,
) -> Result<Box<dyn crate::proxy::ProxyStream>> {
    // mihomo compat: retry() with context timeout (tunnel.go:554-591, 695-716).
    // Entire retry loop bounded by DefaultTCPTimeout (5s).
    // Max 10 iterations but the context timeout is the real limit.
    // Backoff uses jitter: duration = Random(min, min * factor^attempt)
    // via slowdown.New() (slowdown.go, backoff.go).
    let proxy_name = handler.name();
    let proxy_proto = handler.proto();
    debug!(
        "Connecting via [{}] {} to {}",
        proxy_proto, proxy_name, target
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
        match timeout(remaining, handler.connect_stream(target, dns)).await {
            Ok(Ok(r)) => {
                // mihomo compat: notify group of successful dial
                if let Some(group) = group {
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
                    let max_dur =
                        (backoff_min_ms * backoff_factor.powi(attempt as i32)).min(backoff_max_ms);
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

    match remote_conn {
        Some(r) => Ok(r),
        None => {
            let e = last_err.unwrap_or_else(|| anyhow::anyhow!("connect timeout"));
            error!(
                "Proxy connect failed after {} attempts [{}] {} -> {}: {}",
                MAX_RETRIES, proxy_name, src, target, e
            );
            // mihomo compat: notify group of failed dial
            // This may trigger an immediate health check after repeated failures.
            if let Some(group) = group {
                group.on_dial_failed(proxy_proto, &e.to_string());
            }
            Err(e)
        }
    }
}

/// The routing decision for one connection: the matched rule, the outbound
/// handler it resolved to, and the chain reported to `/connections`.
struct Route {
    action: Action,
    handler: Arc<dyn crate::proxy::OutboundHandler>,
    /// The proxy group the action named, if any — touched for lazy health checks
    /// and notified of dial success/failure.
    group: Option<Arc<dyn crate::proxy_group::ProxyGroup>>,
    /// mihomo convention: innermost (final proxy) first.
    chains: Vec<String>,
    /// Raw config rule type ("DOMAIN-SUFFIX"); empty when nothing matched.
    rule_type: String,
    rule_payload: String,
}

/// mihomo compat: tunnel.go match() plus the GLOBAL/DIRECT mode short-circuits.
///
/// Resolves the destination IP first if a rule needs it, matches the rule list,
/// touches the matched group (mihomo's `GroupBase.GetProxies(touch=true)`) so
/// lazy health checks know the group is in use, and resolves the action to an
/// outbound handler. Errors if `Action::Proxy(name)` cannot be resolved — no
/// silent DIRECT fallback. See ARCHITECTURE.md "Scope" and the regression tests
/// in src/proxy/mod.rs.
///
/// The engine/manager/resolver are passed in rather than re-read from AppState
/// so a concurrent reload can't split one connection across two generations.
async fn resolve_route(
    rules: &crate::rules::RuleEngine,
    proxies: &crate::proxy::ProxyManager,
    dns: &crate::dns::DnsResolver,
    rule_meta: &mut RuleMetadata,
    mode: &str,
) -> Result<Route> {
    resolve_ip_on_demand(mode, rule_meta, rules, dns).await;

    let (action, rule_type, rule_payload) = if mode == "global" {
        (
            Action::Proxy("GLOBAL".to_string()),
            "MATCH".to_string(),
            String::new(),
        )
    } else if mode == "direct" {
        (Action::Direct, "DIRECT".to_string(), String::new())
    } else {
        rules.match_rules_detailed(rule_meta)
    };

    // Group name (if routed through a proxy group), for the chain and for touch.
    let group_name = match &action {
        Action::Proxy(name) => Some(name.clone()),
        _ => None,
    };
    let group = group_name.as_ref().and_then(|gn| proxies.get_group(gn));
    if let Some(ref group) = group {
        group.touch();
    }

    let handler = proxies.resolve_action(&action)?;
    let proxy_name = handler.name();

    // Build chains: [final_proxy, group_name] (mihomo convention: innermost first)
    let chains = match group_name {
        Some(gn) if gn != proxy_name => vec![proxy_name.to_string(), gn],
        _ => vec![proxy_name.to_string()],
    };

    Ok(Route {
        action,
        handler,
        group,
        chains,
        rule_type,
        rule_payload,
    })
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

/// mihomo compat: tunnel.go:633 logMetadata — build the single info-level line
/// emitted per connection/session. Split out from [`log_metadata`] so the exact
/// wording (which OpenClash's log parser reads) can be asserted in tests.
///
/// `rule_type` is the raw config type ("DOMAIN-SUFFIX"); the display mapping
/// (`RuleType.String()`) happens here so both callers agree.
fn format_metadata_log(
    network: &str,
    src: impl std::fmt::Display,
    target: impl std::fmt::Display,
    mode: &str,
    rule_type: &str,
    rule_payload: &str,
    chain: &str,
) -> String {
    if mode == "global" {
        format!("[{network}] {src} --> {target} using GLOBAL")
    } else if mode == "direct" {
        format!("[{network}] {src} --> {target} using DIRECT")
    } else if rule_type.is_empty() {
        format!("[{network}] {src} --> {target} doesn't match any rule using {chain}")
    } else {
        let rule = crate::rules::rule_type_display(rule_type);
        if rule_payload.is_empty() {
            format!("[{network}] {src} --> {target} match {rule} using {chain}")
        } else {
            format!("[{network}] {src} --> {target} match {rule}({rule_payload}) using {chain}")
        }
    }
}

/// mihomo compat: the one info log per connection (tunnel.go:633 logMetadata),
/// shared by the TCP and UDP paths.
#[allow(clippy::too_many_arguments)]
fn log_metadata(
    network: &str,
    src: impl std::fmt::Display,
    target: impl std::fmt::Display,
    mode: &str,
    rule_type: &str,
    rule_payload: &str,
    chain: &str,
) {
    info!(
        "{}",
        format_metadata_log(network, src, target, mode, rule_type, rule_payload, chain)
    );
}

/// Result of the preHandleMetadata + sniff phase of a TCP connection.
struct SniffOutcome {
    /// Destination host — from the inbound, the FakeIP/redir-host mapping, or
    /// the sniffer.
    domain: Option<String>,
    /// mihomo compat: metadata.SniffHost — recorded for /connections even when
    /// override-destination is false.
    sniff_host: String,
    /// The sniffed host replaced the metadata host; mihomo's replaceDomain also
    /// blanks DstIP so rules match the new domain.
    sniff_overrode: bool,
    /// Bytes consumed by the peek, to be replayed to the outbound.
    peek_buf: Vec<u8>,
}

/// Process that owns the source socket (mihomo metadata.Process / ProcessPath).
///
/// mihomo's FindProcessStrict defers the lookup until a PROCESS-NAME /
/// PROCESS-PATH rule needs it; we look it up up-front, bounded by a 100ms
/// timeout, so a slow /proc scan can't stall the connection.
async fn detect_process(
    config: &crate::config::MiemieConfig,
    src: SocketAddr,
) -> (Option<String>, Option<String>) {
    let find_process_mode = config.find_process_mode.as_deref().unwrap_or("strict");
    if find_process_mode == "off" {
        return (None, None);
    }
    let src_ip = src.ip();
    let src_port = src.port();
    match tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::task::spawn_blocking(move || process::lookup_process(&src_ip, src_port)),
    )
    .await
    {
        Ok(Ok(Some((name, path)))) => (Some(name), Some(path)),
        _ => (None, None),
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

    // Both directions run as futures inside THIS task (not detached spawns) so
    // that aborting the relay task genuinely drops both stream halves and
    // closes the connections (close_connection / close_all rely on this).
    let a_to_b = async move {
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
    };

    let b_to_a = async move {
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
    };

    tokio::join!(a_to_b, b_to_a);
}

/// Connection manager — mihomo tunnel/tunnel.go equivalent.
pub struct ConnectionManager {
    app: Arc<AppState>,
    connections: DashMap<Arc<str>, ConnEntry>,
}

/// Everything tracked for one live connection: static info for the API,
/// live byte counters, and the relay task's abort handle.
struct ConnEntry {
    info: ConnectionInfo,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    abort: tokio::task::AbortHandle,
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
        }
    }

    /// Handle a new TCP connection from the TUN stack (conn_type "tun").
    /// Other inbounds (redir, tproxy, HTTP, SOCKS5) must use
    /// [`Self::handle_tcp_typed`] / [`Self::handle_tcp_with_host`] so IN-TYPE
    /// rules and the `/connections` type field see the real inbound.
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

        // Read current mode from runtime config
        let mode = {
            let rt = self.app.runtime_config.read();
            rt.mode.clone()
        };

        let Some(sniffed) = self
            .sniff_and_override(src, dst, &mut stream, &config, &dns, host_override)
            .await
        else {
            return Ok(());
        };
        let SniffOutcome {
            domain,
            sniff_host,
            sniff_overrode,
            peek_buf,
        } = sniffed;

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

        let (proc_name, proc_path) = detect_process(&config, src).await;

        // Determine inbound listener port from connection type and config
        let in_port = inbound_port(&config, conn_type);

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

        // mihomo compat: resolveMetadata — a hosts-mapped domain resolves once
        // here; the IP is used both for rule matching (set BEFORE matching,
        // tunnel.go:329-332, so IP-CIDR/GEOIP rules match the hosts-mapped
        // address) and for the dial target override below.
        let hosts_ip: Option<std::net::IpAddr> = domain.as_deref().and_then(|d| {
            config
                .hosts
                .get(&d.to_lowercase())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .filter(|ip| !dns.is_fake_ip(ip))
        });

        let mut rule_meta = RuleMetadata {
            domain: domain.clone(),
            dst_ip: hosts_ip.or(rule_dst_ip),
            src_ip: Some(src.ip()),
            dst_port: dst.port(),
            src_port: src.port(),
            network: "tcp",
            process_name: proc_name,
            process_path: proc_path.clone(),
            in_port,
            in_type: Some(inbound_type_display(conn_type)),
            ..Default::default()
        };

        let route = resolve_route(&rules, &proxies, &dns, &mut rule_meta, &mode).await?;
        let Route {
            action,
            handler,
            group: group_arc,
            chains,
            rule_type,
            rule_payload,
        } = route;

        debug!(
            "TCP {} -> {} ({}) => {:?} [{}]",
            src,
            target,
            domain.as_deref().unwrap_or(""),
            action,
            rule_type
        );

        // Determine the rule string for the connection entry.
        // mihomo compat: the /connections `rule` field uses RuleType.String()
        // display form (e.g. "DomainSuffix", "Match"), not config syntax.
        let rule_str = crate::rules::rule_type_display(&rule_type).to_string();

        // mihomo compat: apply the hosts override (resolved once above) to the
        // dial target: if host is in DefaultHosts and the resolved IP is not a
        // FakeIP, override DstIP.
        let target = if let Some(ip) = hosts_ip {
            debug!(
                "Hosts override: {} -> {}",
                domain.as_deref().unwrap_or(""),
                ip
            );
            Address::ip(SocketAddr::new(ip, dst.port()))
        } else {
            target
        };

        let remote = dial_with_retry(&handler, group_arc.as_ref(), &target, &dns, src).await?;

        let conn_id: Arc<str> = uuid::Uuid::new_v4().to_string().into();
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
        log_metadata(
            "TCP",
            src,
            &target,
            &mode,
            &rule_type,
            &conn_info.rule_payload,
            &chain_display(&conn_info.chains),
        );

        self.register_and_relay(conn_info, stream, remote).await;

        Ok(())
    }

    /// Register the connection so `/connections` can see and close it, relay
    /// both directions to completion, then flush its byte totals into the
    /// global stats and deregister.
    async fn register_and_relay<L, R>(&self, info: ConnectionInfo, local: L, remote: R)
    where
        L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let conn_id = info.id.clone();
        let up_counter = Arc::new(AtomicU64::new(0));
        let down_counter = Arc::new(AtomicU64::new(0));
        let remote_counted = CountingStream::new(remote, up_counter.clone(), down_counter.clone());

        let relay_handle = tokio::spawn(async move {
            relay_bidirectional(local, remote_counted).await;
        });
        self.connections.insert(
            conn_id.clone(),
            ConnEntry {
                info,
                upload: up_counter.clone(),
                download: down_counter.clone(),
                abort: relay_handle.abort_handle(),
            },
        );
        let stats = &self.app.stats;
        stats.add_connection();

        // Wait for the relay to complete (normally or via abort from close_connection)
        let _ = relay_handle.await;

        // Flush totals into global stats
        stats.add_upload(up_counter.load(Ordering::Relaxed));
        stats.add_download(down_counter.load(Ordering::Relaxed));
        stats.remove_connection();
        self.connections.remove(&conn_id);
    }

    /// mihomo compat: preHandleMetadata + the sniffing flow (tunnel.go
    /// handleTCPConn + component/sniffer/dispatcher.go).
    ///
    /// 1. Try FakeIP / redir-host reverse lookup (preHandleMetadata)
    /// 2. If that failed AND the sniffing gates allow, sniff TLS SNI / HTTP Host
    /// 3. Only drop if BOTH failed for a FakeIP destination
    ///
    /// `None` means the connection must be dropped: either the peer sent nothing
    /// within the peek deadline, or the destination is a FakeIP with no
    /// recoverable domain.
    async fn sniff_and_override<S>(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        stream: &mut S,
        config: &crate::config::MiemieConfig,
        dns: &crate::dns::DnsResolver,
        host_override: Option<String>,
    ) -> Option<SniffOutcome>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
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
            // 1s deadline. A timeout means the peer sent nothing yet, which is
            // valid for a server-speaks-first protocol (SMTP/IMAP/FTP/SSH/…),
            // so sniffing must NOT close the connection merely because this
            // deadline expired: fall through and relay without a sniffed
            // domain. Failure accounting belongs to the shared Fail arm below.
            let first = tokio::time::timeout(
                SNIFF_PEEK_TIMEOUT,
                AsyncReadExt::read(&mut *stream, &mut tmp),
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
                    debug!("[Sniffer] [{}] the data length not enough", dst.ip());
                    sniffer::SniffAttempt::Fail
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
                    match tokio::time::timeout(
                        remaining,
                        AsyncReadExt::read(&mut *stream, &mut tmp),
                    )
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
                        let override_dst = sniff_override.unwrap_or(false);
                        if override_dst {
                            debug!(
                                "[Sniffer] Sniff TCP [{}]-->[{}] success, replace domain [{:?}]-->[{}]",
                                src, dst, domain, sniffed
                            );
                            sniff_host = sniffed.clone();
                            domain = Some(sniffed);
                            pre_handle_failed = false;
                            sniff_overrode = true;
                        } else {
                            // mihomo compat: override-destination false only
                            // sets SniffHost — rules keep matching the original
                            // host/IP, so the sniffed name is NOT adopted.
                            sniff_host = sniffed;
                        }
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
            return None;
        }

        Some(SniffOutcome {
            domain,
            sniff_host,
            sniff_overrode,
            peek_buf,
        })
    }

    /// Resolve a UDP datagram's destination through the rule engine.
    ///
    /// `conn_type` is the inbound tag ("socks5" / "tproxy" / "tun") so IN-TYPE
    /// and IN-PORT rules see the real inbound. `domain_override` carries a
    /// client-supplied domain target (SOCKS5 UDP ATYP_DOMAIN) so DOMAIN rules
    /// can match; `dst` is a placeholder 0.0.0.0 in that case.
    ///
    /// Returns the `Action` to take and the resolved domain (if any).
    pub async fn resolve_udp_action(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        conn_type: &'static str,
        domain_override: Option<String>,
    ) -> (Action, Option<String>) {
        let dns = self.app.dns_resolver();
        let rules = self.app.rule_engine();
        let config = self.app.config();

        let mode = {
            let rt = self.app.runtime_config.read();
            rt.mode.clone()
        };

        let domain = domain_override.or_else(|| dns.reverse_lookup(&dst.ip()));

        // mihomo compat: clear FakeIP from dst_ip (same as TCP path); an
        // inbound-supplied domain uses an unspecified placeholder IP that must
        // not leak into IP rules either.
        let rule_dst_ip =
            if dns.is_fake_ip(&dst.ip()) || (domain.is_some() && dst.ip().is_unspecified()) {
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
            in_port: inbound_port(&config, conn_type),
            in_type: Some(inbound_type_display(conn_type)),
            ..Default::default()
        };

        resolve_ip_on_demand(&mode, &mut rule_meta, &rules, &dns).await;

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
            // Same chain shape as the TCP path: innermost element first, so
            // chain_display renders `group[node]`.
            let chains = match &action {
                Action::Direct => vec!["DIRECT".to_string()],
                Action::Reject => vec!["REJECT".to_string()],
                Action::RejectDrop => vec!["REJECT-DROP".to_string()],
                Action::Proxy(name) => {
                    let final_name = proxies
                        .resolve(name)
                        .map(|h| h.name().to_string())
                        .unwrap_or_default();
                    if final_name.is_empty() || final_name == *name {
                        vec![name.clone()]
                    } else {
                        vec![final_name, name.clone()]
                    }
                }
            };
            log_metadata(
                "UDP",
                src,
                &target_str,
                &mode,
                &rule_type,
                &rule_payload,
                &chain_display(&chains),
            );
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
                let e = entry.value();
                let mut info = e.info.clone();
                // Read live counter values instead of the stale zeros stored at insert time
                info.upload = e.upload.load(Ordering::Relaxed);
                info.download = e.download.load(Ordering::Relaxed);
                info
            })
            .collect();

        ConnectionSnapshot {
            download_total: self.app.stats.download_total(),
            upload_total: self.app.stats.upload_total(),
            connections,
            memory: crate::common::mem::get_memory_usage(),
        }
    }

    /// Close all active connections by aborting their relay tasks.
    /// Both relay directions run inside the aborted task (no detached inner
    /// spawns), so aborting drops both stream halves and closes the TCP
    /// connections immediately.
    pub fn close_all(&self) {
        for entry in self.connections.iter() {
            entry.value().abort.abort();
        }
        self.connections.clear();
    }

    /// Close a specific connection by ID, aborting its relay task.
    pub fn close_connection(&self, id: &str) -> bool {
        if let Some((_, entry)) = self.connections.remove(id) {
            entry.abort.abort();
            true
        } else {
            false
        }
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
        Self::default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// mihomo compat: tunnel.go:633 logMetadata — OpenClash's log parser reads
    /// these lines, so the wording is pinned byte-for-byte. The TCP and UDP
    /// paths share one formatter; the only difference is the `[TCP]`/`[UDP]` tag.
    #[test]
    fn metadata_log_lines_match_mihomo() {
        let src = "192.168.1.2:5555";
        let dst = "example.com:443";
        let chain = "Proxy[HK-01]";

        assert_eq!(
            format_metadata_log("TCP", src, dst, "global", "MATCH", "", chain),
            "[TCP] 192.168.1.2:5555 --> example.com:443 using GLOBAL"
        );
        assert_eq!(
            format_metadata_log("TCP", src, dst, "direct", "DIRECT", "", chain),
            "[TCP] 192.168.1.2:5555 --> example.com:443 using DIRECT"
        );
        // No rule matched: mihomo's default branch still names the chain.
        assert_eq!(
            format_metadata_log("TCP", src, dst, "rule", "", "", "DIRECT"),
            "[TCP] 192.168.1.2:5555 --> example.com:443 doesn't match any rule using DIRECT"
        );
        // Payload present -> `Type(payload)`; raw config type is display-mapped.
        assert_eq!(
            format_metadata_log("TCP", src, dst, "rule", "DOMAIN-SUFFIX", "example.com", chain),
            "[TCP] 192.168.1.2:5555 --> example.com:443 match DomainSuffix(example.com) using Proxy[HK-01]"
        );
        // MATCH carries no payload -> bare type.
        assert_eq!(
            format_metadata_log("UDP", src, "1.1.1.1:53", "rule", "MATCH", "", "DIRECT"),
            "[UDP] 192.168.1.2:5555 --> 1.1.1.1:53 match Match using DIRECT"
        );
    }

    /// mihomo compat: constant/adapters.go Chain.String().
    #[test]
    fn chain_display_renders_last_first() {
        assert_eq!(chain_display(&[]), "");
        assert_eq!(chain_display(&["DIRECT".to_string()]), "DIRECT");
        assert_eq!(
            chain_display(&["HK-01".to_string(), "Proxy".to_string()]),
            "Proxy[HK-01]"
        );
        // Deeper chains render outermost[innermost], dropping the middle.
        assert_eq!(
            chain_display(&["HK-01".to_string(), "Auto".to_string(), "Proxy".to_string()]),
            "Proxy[HK-01]"
        );
    }

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
        assert_eq!(stream.read(&mut buf).await.unwrap(), 3);
        assert_eq!(stream.read(&mut buf).await.unwrap(), 5);
        assert_eq!(stream.write(b"12").await.unwrap(), 2);
        assert_eq!(stream.write(b"3456").await.unwrap(), 4);

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

    /// C1 regression: each inbound type maps to its own listener port and
    /// mihomo Type.String() — redir/tproxy must not be lumped in as "tun".
    #[test]
    fn inbound_port_per_type() {
        let config: crate::config::MiemieConfig = serde_yaml::from_str(
            "port: 7890\nsocks-port: 7891\nredir-port: 7892\ntproxy-port: 7895\nmixed-port: 7893\n",
        )
        .unwrap();
        assert_eq!(inbound_port(&config, "http-connect"), Some(7890));
        assert_eq!(inbound_port(&config, "socks5"), Some(7891));
        assert_eq!(inbound_port(&config, "redir"), Some(7892));
        assert_eq!(inbound_port(&config, "tun"), Some(7892));
        assert_eq!(inbound_port(&config, "tproxy"), Some(7895));
    }

    #[test]
    fn inbound_type_display_maps_mihomo_names() {
        assert_eq!(inbound_type_display("http-connect"), "HTTP");
        assert_eq!(inbound_type_display("socks5"), "Socks5");
        assert_eq!(inbound_type_display("redir"), "Redir");
        assert_eq!(inbound_type_display("tproxy"), "TProxy");
        assert_eq!(inbound_type_display("tun"), "Tun");
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
