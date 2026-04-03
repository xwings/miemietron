use anyhow::Result;
use dashmap::DashMap;
use pin_project_lite::pin_project;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::common::addr::Address;
use crate::rules::{process, Action, RuleMetadata};
use crate::sniffer;
use crate::AppState;

// ---------------------------------------------------------------------------
// CountingStream — wraps any AsyncRead+AsyncWrite and counts bytes transferred
// ---------------------------------------------------------------------------

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

    pub fn upload_bytes(&self) -> u64 {
        self.upload.load(Ordering::Relaxed)
    }

    pub fn download_bytes(&self) -> u64 {
        self.download.load(Ordering::Relaxed)
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

// ---------------------------------------------------------------------------
// PeekableStream — replays buffered prefix bytes then delegates to the inner stream
// ---------------------------------------------------------------------------

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

/// Manages active connections and orchestrates the proxy pipeline.
///
/// Reads from the shared `AppState` on each new connection, so hot-reloaded
/// configs, rules, proxies, and DNS are picked up immediately for new
/// connections while existing connections continue with their snapshotted state.
pub struct ConnectionManager {
    app: Arc<AppState>,
    connections: DashMap<String, ConnectionInfo>,
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub conn_type: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    pub host: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
    #[serde(rename = "processPath")]
    pub process_path: String,
    #[serde(rename = "specialProxy")]
    pub special_proxy: String,
    #[serde(rename = "specialRules")]
    pub special_rules: String,
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

    /// Handle a new TCP connection from the TUN stack.
    pub async fn handle_tcp(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    ) -> Result<()> {
        self.handle_tcp_typed(src, dst, stream, "tun").await
    }

    /// Inner implementation that also accepts a connection-type tag (e.g. "tun",
    /// "http-proxy", "socks5").
    pub async fn handle_tcp_typed(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        conn_type: &str,
    ) -> Result<()> {
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

        // Resolve domain from FakeIP
        let mut domain = dns.reverse_lookup(&dst.ip());

        // ---- Sniff: peek first bytes for TLS SNI / HTTP Host ----
        // Read up to SNIFF_PEEK_SIZE bytes from the client without consuming them.
        // We'll wrap the stream in PeekableStream to replay these bytes later.
        let mut peek_buf = vec![0u8; SNIFF_PEEK_SIZE];
        let peeked_len = match tokio::io::AsyncReadExt::read(&mut stream, &mut peek_buf).await {
            Ok(n) => n,
            Err(e) => {
                debug!("Sniff peek read failed: {}", e);
                0
            }
        };
        peek_buf.truncate(peeked_len);

        let mut sniff_host = String::new();
        if peeked_len > 0 {
            if let Some(sniffed) = sniffer::sniff_domain(&peek_buf) {
                sniff_host = sniffed.clone();
                if domain.is_none() {
                    debug!(
                        "Sniffed domain '{}' for {} -> {} (no FakeIP)",
                        sniffed, src, dst
                    );
                    domain = Some(sniffed);
                } else {
                    debug!(
                        "Sniffed domain '{}' for {} -> {} (FakeIP: {})",
                        sniffed,
                        src,
                        dst,
                        domain.as_deref().unwrap_or("")
                    );
                }
            }
        }

        // Wrap the stream so the peeked bytes are replayed before the rest
        let stream = PeekableStream::new(peek_buf, stream);

        let target = if let Some(ref domain) = domain {
            Address::domain(domain, dst.port())
        } else {
            Address::ip(dst)
        };

        // Process detection: look up the process that owns this source socket.
        // Only do this if find-process-mode is not "off" (default is to detect).
        let find_process_mode = config.find_process_mode.as_deref().unwrap_or("always");
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

        // Build rule metadata
        let rule_meta = RuleMetadata {
            domain: domain.clone(),
            dst_ip: Some(dst.ip()),
            src_ip: Some(src.ip()),
            dst_port: dst.port(),
            src_port: src.port(),
            network: "tcp".to_string(),
            process_name: proc_name.clone(),
            process_path: proc_path.clone(),
        };

        // Match rules
        let (action, rule_type, rule_payload) = if mode == "global" {
            if let Some(group) = config.proxy_groups.first() {
                (
                    Action::Proxy(group.name.clone()),
                    "MATCH".to_string(),
                    String::new(),
                )
            } else {
                (Action::Direct, "MATCH".to_string(), String::new())
            }
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

        // Get outbound handler
        let handler = match &action {
            Action::Direct => proxies.get("DIRECT"),
            Action::Reject => proxies.get("REJECT"),
            Action::RejectDrop => proxies.get("REJECT-DROP"),
            Action::Proxy(name) => proxies.resolve(name),
        };

        let handler = handler.unwrap_or_else(|| proxies.get("DIRECT").unwrap());
        let proxy_name = handler.name().to_string();

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

        // Connect through proxy
        let remote = handler.connect_stream(&target, &dns).await?;

        // --- Per-connection byte counters ---
        let conn_id = uuid::Uuid::new_v4().to_string();
        let up_counter = Arc::new(AtomicU64::new(0));
        let down_counter = Arc::new(AtomicU64::new(0));

        // Register connection in the DashMap
        let conn_info = ConnectionInfo {
            id: conn_id.clone(),
            metadata: ConnectionMetadata {
                network: "tcp".to_string(),
                conn_type: conn_type.to_string(),
                source_ip: src.ip().to_string(),
                destination_ip: dst.ip().to_string(),
                source_port: src.port().to_string(),
                destination_port: dst.port().to_string(),
                host: domain.clone().unwrap_or_default(),
                dns_mode: if domain.is_some() {
                    "fake-ip".to_string()
                } else {
                    String::new()
                },
                process_path: proc_path.unwrap_or_default(),
                special_proxy: String::new(),
                special_rules: String::new(),
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
        stats.add_connection();

        // Wrap both sides with CountingStream
        let local_counted = CountingStream::new(stream, up_counter.clone(), down_counter.clone());
        let remote_counted = CountingStream::new(remote, up_counter.clone(), down_counter.clone());

        // Bidirectional relay
        let (mut local_read, mut local_write) = tokio::io::split(local_counted);
        let (mut remote_read, mut remote_write) = tokio::io::split(remote_counted);

        let client_to_remote = tokio::io::copy(&mut local_read, &mut remote_write);
        let remote_to_client = tokio::io::copy(&mut remote_read, &mut local_write);

        let _ = tokio::try_join!(client_to_remote, remote_to_client);

        // Flush totals into global stats
        let up = up_counter.load(Ordering::Relaxed);
        let down = down_counter.load(Ordering::Relaxed);
        stats.add_upload(up);
        stats.add_download(down);
        stats.remove_connection();
        self.connections.remove(&conn_id);

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
            network: "udp".to_string(),
            process_name: None,
            process_path: None,
        };

        let action = if mode == "global" {
            if let Some(group) = config.proxy_groups.first() {
                Action::Proxy(group.name.clone())
            } else {
                Action::Direct
            }
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
    pub fn snapshot(&self) -> ConnectionSnapshot {
        let connections: Vec<ConnectionInfo> = self
            .connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        ConnectionSnapshot {
            download_total: self.app.stats.download_total(),
            upload_total: self.app.stats.upload_total(),
            connections,
            memory: get_memory_usage(),
        }
    }

    /// Close all active connections.
    pub fn close_all(&self) {
        self.connections.clear();
    }

    /// Close a specific connection by ID.
    pub fn close_connection(&self, id: &str) -> bool {
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
