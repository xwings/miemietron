use anyhow::Result;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::debug;

use crate::common::addr::Address;
use crate::config::MiemieConfig;
use crate::dns::DnsResolver;
use crate::proxy::ProxyManager;
use crate::rules::{Action, RuleEngine, RuleMetadata};

/// Manages active connections and orchestrates the proxy pipeline.
pub struct ConnectionManager {
    dns: Arc<DnsResolver>,
    rules: Arc<RuleEngine>,
    proxies: Arc<ProxyManager>,
    stats: Arc<StatsManager>,
    config: Arc<MiemieConfig>,
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
    pub fn new(
        dns: Arc<DnsResolver>,
        rules: Arc<RuleEngine>,
        proxies: Arc<ProxyManager>,
        stats: Arc<StatsManager>,
        config: Arc<MiemieConfig>,
    ) -> Self {
        Self {
            dns,
            rules,
            proxies,
            stats,
            config,
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
        // Resolve domain from FakeIP
        let domain = self.dns.reverse_lookup(&dst.ip());

        let target = if let Some(ref domain) = domain {
            Address::domain(domain, dst.port())
        } else {
            Address::ip(dst)
        };

        // Build rule metadata
        let metadata = RuleMetadata {
            domain: domain.clone(),
            dst_ip: Some(dst.ip()),
            src_ip: Some(src.ip()),
            dst_port: dst.port(),
            src_port: src.port(),
            network: "tcp".to_string(),
            process_name: None,
            process_path: None,
        };

        // Match rules
        let action = if self.config.mode == "global" {
            // Global mode: use first proxy group
            if let Some(group) = self.config.proxy_groups.first() {
                Action::Proxy(group.name.clone())
            } else {
                Action::Direct
            }
        } else if self.config.mode == "direct" {
            Action::Direct
        } else {
            self.rules.match_rules(&metadata)
        };

        debug!(
            "TCP {} -> {} ({}) => {:?}",
            src,
            target,
            domain.as_deref().unwrap_or(""),
            action
        );

        // Get outbound handler
        let handler = match &action {
            Action::Direct => self.proxies.get("DIRECT"),
            Action::Reject => self.proxies.get("REJECT"),
            Action::RejectDrop => self.proxies.get("REJECT-DROP"),
            Action::Proxy(name) => self.proxies.resolve(name),
        };

        let handler = handler.unwrap_or_else(|| self.proxies.get("DIRECT").unwrap());

        // Connect through proxy
        let remote = handler.connect_stream(&target, &self.dns).await?;

        // Track connection
        let conn_id = uuid::Uuid::new_v4().to_string();
        self.stats.add_connection();

        // Bidirectional relay between TUN stream and proxy stream
        let (mut local_read, mut local_write) = tokio::io::split(stream);
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);

        let up_stats = self.stats.clone();
        let down_stats = self.stats.clone();

        let client_to_remote = async {
            let n = tokio::io::copy(&mut local_read, &mut remote_write).await;
            if let Ok(bytes) = n {
                up_stats.add_upload(bytes);
            }
            n
        };

        let remote_to_client = async {
            let n = tokio::io::copy(&mut remote_read, &mut local_write).await;
            if let Ok(bytes) = n {
                down_stats.add_download(bytes);
            }
            n
        };

        let _ = tokio::try_join!(client_to_remote, remote_to_client);

        self.stats.remove_connection();
        self.connections.remove(&conn_id);

        Ok(())
    }

    /// Get a snapshot of all active connections (for API).
    pub fn snapshot(&self) -> ConnectionSnapshot {
        let connections: Vec<ConnectionInfo> = self
            .connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        ConnectionSnapshot {
            download_total: self.stats.download_total(),
            upload_total: self.stats.upload_total(),
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
