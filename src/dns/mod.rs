pub mod cache;
pub mod fakeip;
pub mod upstream;

use anyhow::Result;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info};

use crate::config::DnsConfig;
use cache::DnsCache;
use fakeip::FakeIpPool;

type GeositeCheckerFn = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

pub struct DnsResolver {
    config: DnsConfig,
    cache: DnsCache,
    fakeip: Option<FakeIpPool>,
    hosts: std::collections::HashMap<String, IpAddr>,
    /// Geosite codes from fake-ip-filter (e.g. "geosite:cn" → "cn").
    fakeip_geosite_codes: Vec<String>,
    /// Callback to check if a domain matches a geosite code.
    /// Set after construction via `set_geosite_checker()`.
    geosite_checker: Option<GeositeCheckerFn>,
    /// Reverse IP→domain mapping for redir-host mode and traffic logging.
    /// Records every DNS resolution result (both FakeIP and real IPs).
    /// Matches mihomo's dns/enhancer.go mapping LRU.
    /// Value is (domain, expiry instant).
    ip_to_host: DashMap<IpAddr, (String, Instant)>,
    /// Cache for proxy server hostname resolution (avoids DNS storm).
    /// Key: domain, Value: (resolved IP, expiry instant).
    /// TTL = 120 seconds — long enough to prevent storms, short enough to follow DNS changes.
    proxy_dns_cache: DashMap<String, (IpAddr, Instant)>,
    /// Per-domain singleflight for proxy server DNS to dedup concurrent queries.
    /// Key: domain, Value: mutex guarding the in-flight resolution.
    proxy_dns_inflight: DashMap<String, Arc<TokioMutex<()>>>,
}

impl DnsResolver {
    pub async fn new(config: &DnsConfig) -> Result<Self> {
        Self::with_hosts(config, &std::collections::HashMap::new()).await
    }

    /// Create a new resolver with an explicit hosts map (from config.hosts).
    pub async fn with_hosts(
        config: &DnsConfig,
        hosts_map: &std::collections::HashMap<String, String>,
    ) -> Result<Self> {
        let cache = DnsCache::new(config.cache_max_size as usize);

        let fakeip = if config.enable && config.enhanced_mode == "fake-ip" {
            Some(FakeIpPool::new(
                &config.fake_ip_range,
                &config.fake_ip_filter,
                &config.fake_ip_filter_mode,
            )?)
        } else {
            None
        };

        // Parse hosts map: string → IpAddr, skip entries that don't parse
        let hosts = hosts_map
            .iter()
            .filter_map(|(domain, ip_str)| {
                ip_str.parse::<IpAddr>().ok().map(|ip| (domain.to_lowercase(), ip))
            })
            .collect();

        // Extract geosite: entries from fake-ip-filter for bypass checking.
        // e.g. "geosite:cn" means all domains in the GeoSite "cn" group should
        // bypass FakeIP and get real IP resolution instead.
        let fakeip_geosite_codes: Vec<String> = config
            .fake_ip_filter
            .iter()
            .filter_map(|f| f.strip_prefix("geosite:").map(|s| s.to_lowercase()))
            .collect();
        if !fakeip_geosite_codes.is_empty() {
            info!(
                "FakeIP bypass geosite codes: {:?}",
                fakeip_geosite_codes
            );
        }

        Ok(Self {
            config: config.clone(),
            cache,
            fakeip,
            hosts,
            fakeip_geosite_codes,
            geosite_checker: None,
            ip_to_host: DashMap::new(),
            proxy_dns_cache: DashMap::new(),
            proxy_dns_inflight: DashMap::new(),
        })
    }

    /// Set a geosite checker function for fake-ip-filter geosite bypass.
    /// Called after construction once the RuleEngine (with GeoSite.dat) is built.
    pub fn set_geosite_checker<F>(&mut self, checker: F)
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.geosite_checker = Some(Arc::new(checker));
    }

    /// Check if a domain should bypass FakeIP (get real IP instead).
    fn should_bypass_fakeip(&self, domain: &str) -> bool {
        // Check the pool's pattern-based filter (*.lan, +.qq.com, etc.)
        if let Some(ref pool) = self.fakeip {
            if pool.should_bypass(domain) {
                return true;
            }
        }

        // Check geosite-based filter (e.g. "geosite:cn")
        if !self.fakeip_geosite_codes.is_empty() {
            if let Some(ref checker) = self.geosite_checker {
                for code in &self.fakeip_geosite_codes {
                    if checker(domain, code) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Resolve a domain name. In fake-ip mode, returns a fake IP.
    /// In redir-host mode, queries upstream DNS.
    ///
    /// mihomo compat: all resolution results (both FakeIP and real IPs) are
    /// recorded in the ip_to_host mapping for reverse lookups, matching
    /// mihomo's withMapping() middleware in dns/middleware.go.
    pub async fn resolve(&self, domain: &str) -> Result<IpAddr> {
        // Check hosts map first (highest priority, like /etc/hosts)
        if let Some(ip) = self.hosts.get(&domain.to_lowercase()) {
            // mihomo compat: withHosts() also records into the mapping
            self.record_ip_mapping(*ip, domain, 10);
            return Ok(*ip);
        }

        // Check cache
        if let Some(ip) = self.cache.get(domain) {
            return Ok(ip);
        }

        // FakeIP mode: assign a fake IP — unless the domain is in the bypass filter.
        // Bypassed domains (e.g. *.lan, geosite:cn, NTP servers, music services)
        // get resolved to real IPs via upstream DNS instead.
        if let Some(ref pool) = self.fakeip {
            if self.should_bypass_fakeip(domain) {
                // Filtered domain: resolve to real IP (redir-host behavior)
                let (ip, ttl) = self.query_upstream_with_ttl(domain).await?;
                self.cache.insert(domain.to_string(), ip, ttl);
                // mihomo compat: withMapping() records bypassed FakeIP resolutions too
                self.record_ip_mapping(ip, domain, ttl);
                return Ok(ip);
            }
            // mihomo compat: FakeIP allocations are NOT cached in the DNS cache.
            // They are already stored in the FakeIP pool which handles its own
            // domain <-> IP mapping. Caching them here would be redundant and
            // would prevent the FakeIP pool from being the single source of truth.
            let ip = pool.allocate(domain);
            // Also record in ip_to_host for consistency (FakeIP pool is authoritative,
            // but the general mapping provides a unified reverse lookup path)
            self.record_ip_mapping(ip, domain, FAKEIP_TTL);
            return Ok(ip);
        }

        // Redir-host mode: query upstream
        let (ip, ttl) = self.query_upstream_with_ttl(domain).await?;
        self.cache.insert(domain.to_string(), ip, ttl);
        // mihomo compat: withMapping() records every upstream resolution
        self.record_ip_mapping(ip, domain, ttl);
        Ok(ip)
    }

    /// Reverse-lookup: given an IP, return the original domain.
    ///
    /// mihomo compat: matches enhancer.go FindHostByIP() — checks FakeIP pool
    /// first (authoritative for FakeIP range), then the general ip_to_host
    /// mapping (for redir-host mode + real IP logging).
    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<String> {
        // Check FakeIP pool first (authoritative for FakeIP range)
        if let Some(ref pool) = self.fakeip {
            if let Some(domain) = pool.lookup_domain(ip) {
                return Some(domain);
            }
        }
        // Check the general IP→host mapping (for redir-host mode + logging)
        if let Some(entry) = self.ip_to_host.get(ip) {
            let (ref domain, ref expires_at) = *entry;
            if Instant::now() < *expires_at {
                return Some(domain.clone());
            }
            // Entry expired — remove it
            drop(entry);
            self.ip_to_host.remove(ip);
        }
        None
    }

    /// mihomo compat: withMapping() in dns/middleware.go.
    fn record_ip_mapping(&self, ip: IpAddr, domain: &str, ttl: u32) {
        let ttl = ttl.max(1);
        let expires_at = Instant::now() + std::time::Duration::from_secs(ttl as u64);
        if self.ip_to_host.len() > 4096 {
            self.evict_expired_ip_mappings();
        }
        self.ip_to_host.insert(ip, (domain.to_string(), expires_at));
    }

    /// Remove expired entries from ip_to_host to prevent unbounded growth.
    fn evict_expired_ip_mappings(&self) {
        let now = Instant::now();
        self.ip_to_host.retain(|_, (_, expires_at)| now < *expires_at);
    }

    /// Manually insert an IP→domain mapping.
    /// mihomo compat: matches enhancer.go InsertHostByIP().
    pub fn insert_host_by_ip(&self, ip: IpAddr, host: &str) {
        // Use DNS_DEFAULT_TTL (600s) for manually inserted entries
        self.record_ip_mapping(ip, host, DNS_DEFAULT_TTL);
    }

    /// Query upstream DNS servers for a real IP.
    /// Returns only the IP address (TTL is discarded).
    pub async fn query_upstream(&self, domain: &str) -> Result<IpAddr> {
        let (ip, _ttl) = upstream::resolve(domain, &self.config).await?;
        Ok(ip)
    }

    /// Query upstream DNS servers for a real IP and TTL.
    /// Used internally for TTL-aware caching.
    async fn query_upstream_with_ttl(&self, domain: &str) -> Result<(IpAddr, u32)> {
        upstream::resolve(domain, &self.config).await
    }

    /// Resolve a proxy server hostname using only direct/bootstrap DNS.
    ///
    /// Uses `proxy-server-nameserver` or `default-nameserver` from config
    /// (set by OpenClash). Avoids DoH/DoT which may require a proxy that
    /// hasn't been connected yet.
    ///
    /// Results are cached for 120s (success) or 10s (failure) and concurrent
    /// queries for the same domain are deduplicated via per-domain mutex to
    /// prevent DNS storms during health checks / retries.
    pub async fn resolve_proxy_server(&self, domain: &str) -> Result<IpAddr> {
        // If it's already an IP literal, just parse it
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(ip);
        }

        const PROXY_DNS_TTL_OK: Duration = Duration::from_secs(120);
        const PROXY_DNS_TTL_FAIL: Duration = Duration::from_secs(10);

        // Check cache first
        if let Some(entry) = self.proxy_dns_cache.get(domain) {
            let (ip, created) = *entry;
            let ttl = if ip.is_unspecified() {
                PROXY_DNS_TTL_FAIL // negative cache entry
            } else {
                PROXY_DNS_TTL_OK
            };
            if created.elapsed() < ttl {
                if ip.is_unspecified() {
                    return Err(anyhow::anyhow!(
                        "DNS resolution for proxy server '{domain}' failed (cached negative result)"
                    ));
                }
                debug!("DNS proxy-server cache hit: {} -> {}", domain, ip);
                return Ok(ip);
            }
            // Expired — remove stale entry
            drop(entry);
            self.proxy_dns_cache.remove(domain);
        }

        // Singleflight: acquire per-domain mutex to dedup concurrent queries.
        // Only one task actually queries upstream; others wait for the result.
        let mutex = self
            .proxy_dns_inflight
            .entry(domain.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();

        let _guard = mutex.lock().await;

        // Re-check cache after acquiring lock (another task may have populated it)
        if let Some(entry) = self.proxy_dns_cache.get(domain) {
            let (ip, created) = *entry;
            let ttl = if ip.is_unspecified() {
                PROXY_DNS_TTL_FAIL
            } else {
                PROXY_DNS_TTL_OK
            };
            if created.elapsed() < ttl {
                if ip.is_unspecified() {
                    return Err(anyhow::anyhow!(
                        "DNS resolution for proxy server '{domain}' failed (cached negative result)"
                    ));
                }
                debug!("DNS proxy-server cache hit (after dedup): {} -> {}", domain, ip);
                return Ok(ip);
            }
        }

        // Actually resolve
        let result = upstream::resolve_proxy_server(domain, &self.config).await;

        match &result {
            Ok(ip) => {
                // Cache successful result (120s)
                self.proxy_dns_cache
                    .insert(domain.to_string(), (*ip, Instant::now()));
            }
            Err(_) => {
                // Negative cache (10s) — prevents repeated failed queries
                // Uses 0.0.0.0 as sentinel for "failed"
                self.proxy_dns_cache.insert(
                    domain.to_string(),
                    (IpAddr::V4(Ipv4Addr::UNSPECIFIED), Instant::now()),
                );
            }
        }

        result
    }

    /// Check if an IP is in the fake IP range.
    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        if let Some(ref pool) = self.fakeip {
            return pool.contains(ip);
        }
        false
    }

    /// Flush the DNS cache and IP→domain mapping.
    pub fn flush_cache(&self) {
        self.cache.clear();
        self.flush_mapping();
    }

    /// Flush the IP→domain reverse mapping.
    /// mihomo compat: clearing the mapping alongside the cache ensures
    /// stale reverse lookups don't persist after a cache flush.
    pub fn flush_mapping(&self) {
        self.ip_to_host.clear();
    }

    /// Flush the FakeIP pool.
    pub fn flush_fakeip(&self) {
        if let Some(ref pool) = self.fakeip {
            pool.clear();
        }
    }

    /// Save FakeIP mappings to disk.
    pub fn save_fakeip(&self, path: &std::path::Path) -> Result<()> {
        if let Some(ref pool) = self.fakeip {
            pool.save(path)?;
        }
        Ok(())
    }

    /// Load FakeIP mappings from disk.
    pub fn load_fakeip(&self, path: &std::path::Path) -> Result<()> {
        if let Some(ref pool) = self.fakeip {
            pool.load(path)?;
        }
        Ok(())
    }
}

/// Run a DNS server that listens for queries on both UDP and TCP.
pub async fn run_dns_server(listen: &str, resolver: Arc<DnsResolver>) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1053));

    let udp_socket = Arc::new(UdpSocket::bind(addr).await?);
    let tcp_listener = TcpListener::bind(addr).await?;
    info!("DNS server listening on {} (UDP + TCP)", addr);

    // Spawn the TCP listener in a background task
    let tcp_resolver = resolver.clone();
    tokio::spawn(async move {
        run_dns_tcp_server(tcp_listener, tcp_resolver).await;
    });

    // UDP listener (main loop)
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = match udp_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!("DNS UDP recv error: {}", e);
                continue;
            }
        };

        let data = buf[..n].to_vec();
        let resolver = resolver.clone();
        let udp_socket_clone = udp_socket.clone();

        tokio::spawn(async move {
            match parse_dns_query(&data) {
                Some((id, domain, qtype)) => {
                    debug!("DNS query (UDP): {} (type {})", domain, qtype);
                    match resolver.resolve(&domain).await {
                        Ok(ip) => {
                            let ttl = if resolver.is_fake_ip(&ip) { FAKEIP_TTL } else { DNS_DEFAULT_TTL };
                            let response = build_dns_response(id, &domain, ip, qtype, ttl);
                            let _ = udp_socket_clone.send_to(&response, src).await;
                        }
                        Err(e) => {
                            debug!("DNS resolve failed for {}: {}", domain, e);
                            let response = build_dns_servfail(id);
                            let _ = udp_socket_clone.send_to(&response, src).await;
                        }
                    }
                }
                None => {
                    debug!("Failed to parse DNS query (UDP)");
                }
            }
        });
    }
}

/// DNS-over-TCP server: accepts connections and handles DNS queries with
/// 2-byte length prefix framing (RFC 1035 section 4.2.2).
async fn run_dns_tcp_server(listener: TcpListener, resolver: Arc<DnsResolver>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("DNS TCP accept error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dns_tcp_connection(stream, &resolver).await {
                debug!("DNS TCP connection from {} error: {}", peer, e);
            }
        });
    }
}

/// Handle a single DNS-over-TCP connection.
///
/// DNS over TCP uses a 2-byte big-endian length prefix before each message.
/// A single TCP connection can carry multiple queries (pipelining).
async fn handle_dns_tcp_connection(
    mut stream: tokio::net::TcpStream,
    resolver: &DnsResolver,
) -> Result<()> {
    loop {
        // Read the 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed the connection
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            return Ok(()); // Invalid length, close connection
        }

        // Read the DNS message
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        // Process the query
        let response = match parse_dns_query(&msg_buf) {
            Some((id, domain, qtype)) => {
                debug!("DNS query (TCP): {} (type {})", domain, qtype);
                match resolver.resolve(&domain).await {
                    Ok(ip) => {
                        let ttl = if resolver.is_fake_ip(&ip) { FAKEIP_TTL } else { DNS_DEFAULT_TTL };
                        build_dns_response(id, &domain, ip, qtype, ttl)
                    }
                    Err(e) => {
                        debug!("DNS resolve failed for {}: {}", domain, e);
                        build_dns_servfail(id)
                    }
                }
            }
            None => {
                debug!("Failed to parse DNS query (TCP)");
                continue;
            }
        };

        // Write 2-byte length prefix + response
        let resp_len = (response.len() as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
    }
}

/// Minimal DNS query parser (extracts question domain and type).
fn parse_dns_query(data: &[u8]) -> Option<(u16, String, u16)> {
    if data.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);

    // Parse question section
    let mut pos = 12;
    let mut domain_parts = Vec::new();

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > data.len() {
            return None;
        }
        domain_parts.push(String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]).to_string());
        pos += 1 + len;
    }

    if pos + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let domain = domain_parts.join(".");

    Some((id, domain, qtype))
}

/// mihomo compat: FakeIP responses use TTL=1, real responses use TTL=600.
const FAKEIP_TTL: u32 = 1;
const DNS_DEFAULT_TTL: u32 = 600;

/// Build a DNS response. The question type must match the original query.
/// For AAAA queries with IPv4 FakeIP, return NODATA (0 answers, correct question type).
/// mihomo compat: browsers send both A and AAAA queries; mismatched responses get discarded.
fn build_dns_response(id: u16, domain: &str, ip: IpAddr, qtype: u16, ttl: u32) -> Vec<u8> {
    const TYPE_A: u16 = 1;
    const TYPE_AAAA: u16 = 28;

    // Check if we have a type mismatch (AAAA query but IPv4 answer, or A query but IPv6 answer)
    let type_mismatch = matches!(
        (&ip, qtype),
        (IpAddr::V4(_), TYPE_AAAA) | (IpAddr::V6(_), TYPE_A)
    );

    let mut response = Vec::with_capacity(128);

    // Header
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&[0x81, 0x80]); // Flags: response, recursion desired+available
    response.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    if type_mismatch {
        response.extend_from_slice(&[0x00, 0x00]); // Answers: 0 (NODATA)
    } else {
        response.extend_from_slice(&[0x00, 0x01]); // Answers: 1
    }
    response.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    response.extend_from_slice(&[0x00, 0x00]); // Additional: 0

    // Question section — must echo back the ORIGINAL query type
    for part in domain.split('.') {
        response.push(part.len() as u8);
        response.extend_from_slice(part.as_bytes());
    }
    response.push(0);
    response.extend_from_slice(&qtype.to_be_bytes()); // Original query type
    response.extend_from_slice(&[0x00, 0x01]); // Class IN

    // Answer section — only if types match
    if !type_mismatch {
        response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to question
        match ip {
            IpAddr::V4(ipv4) => {
                response.extend_from_slice(&[0x00, 0x01]); // Type A
                response.extend_from_slice(&[0x00, 0x01]); // Class IN
                response.extend_from_slice(&ttl.to_be_bytes());
                response.extend_from_slice(&[0x00, 0x04]);
                response.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                response.extend_from_slice(&[0x00, 0x1c]); // Type AAAA
                response.extend_from_slice(&[0x00, 0x01]); // Class IN
                response.extend_from_slice(&ttl.to_be_bytes());
                response.extend_from_slice(&[0x00, 0x10]);
                response.extend_from_slice(&ipv6.octets());
            }
        }
    }

    response
}

/// Build a minimal DNS SERVFAIL response.
fn build_dns_servfail(id: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(12);
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&[0x81, 0x82]); // Response + SERVFAIL
    response.extend_from_slice(&[0x00, 0x00]); // 0 questions
    response.extend_from_slice(&[0x00, 0x00]); // 0 answers
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Helper: create a minimal DnsResolver for testing (no FakeIP, no upstream).
    fn test_resolver() -> DnsResolver {
        DnsResolver {
            config: DnsConfig::default(),
            cache: DnsCache::new(100),
            fakeip: None,
            hosts: std::collections::HashMap::new(),
            fakeip_geosite_codes: Vec::new(),
            geosite_checker: None,
            ip_to_host: DashMap::new(),
            proxy_dns_cache: DashMap::new(),
            proxy_dns_inflight: DashMap::new(),
        }
    }

    #[test]
    fn record_and_reverse_lookup_ip_mapping() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // No mapping yet
        assert_eq!(resolver.reverse_lookup(&ip), None);

        // Record a mapping with 600s TTL
        resolver.record_ip_mapping(ip, "example.com", 600);

        // Now reverse lookup should succeed
        assert_eq!(resolver.reverse_lookup(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn insert_host_by_ip_public_api() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        resolver.insert_host_by_ip(ip, "dns.google");
        assert_eq!(resolver.reverse_lookup(&ip), Some("dns.google".to_string()));
    }

    #[test]
    fn mapping_overwrites_previous_entry() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        resolver.record_ip_mapping(ip, "first.example.com", 300);
        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("first.example.com".to_string())
        );

        // Overwrite with new domain (same IP, different CNAME target)
        resolver.record_ip_mapping(ip, "second.example.com", 300);
        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("second.example.com".to_string())
        );
    }

    #[test]
    fn expired_mapping_returns_none_and_is_removed() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Insert with an already-expired entry (simulate by inserting directly)
        let expired = Instant::now() - std::time::Duration::from_secs(1);
        resolver
            .ip_to_host
            .insert(ip, ("expired.example.com".to_string(), expired));

        // Should return None because the entry is expired
        assert_eq!(resolver.reverse_lookup(&ip), None);

        // The expired entry should have been cleaned up
        assert!(!resolver.ip_to_host.contains_key(&ip));
    }

    #[test]
    fn zero_ttl_gets_minimum_one_second() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

        // mihomo compat: TTL of 0 should be clamped to 1 second
        resolver.record_ip_mapping(ip, "zero-ttl.example.com", 0);

        // Should still be retrievable (1 second hasn't elapsed)
        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("zero-ttl.example.com".to_string())
        );
    }

    #[test]
    fn flush_mapping_clears_all_entries() {
        let resolver = test_resolver();

        resolver.record_ip_mapping(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            "one.example.com",
            600,
        );
        resolver.record_ip_mapping(
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            "two.example.com",
            600,
        );

        assert_eq!(resolver.ip_to_host.len(), 2);

        resolver.flush_mapping();

        assert_eq!(resolver.ip_to_host.len(), 0);
        assert_eq!(
            resolver.reverse_lookup(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            None
        );
    }

    #[test]
    fn flush_cache_also_flushes_mapping() {
        let resolver = test_resolver();

        resolver.record_ip_mapping(
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
            "three.example.com",
            600,
        );
        assert_eq!(resolver.ip_to_host.len(), 1);

        resolver.flush_cache();

        assert_eq!(resolver.ip_to_host.len(), 0);
    }

    #[test]
    fn multiple_ips_for_different_domains() {
        let resolver = test_resolver();

        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46));

        resolver.record_ip_mapping(ip1, "example.com", 300);
        resolver.record_ip_mapping(ip2, "google.com", 300);

        assert_eq!(resolver.reverse_lookup(&ip1), Some("example.com".to_string()));
        assert_eq!(resolver.reverse_lookup(&ip2), Some("google.com".to_string()));
    }

    #[test]
    fn ipv6_mapping_works() {
        let resolver = test_resolver();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        resolver.record_ip_mapping(ip, "ipv6.example.com", 600);

        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("ipv6.example.com".to_string())
        );
    }

    #[test]
    fn reverse_lookup_no_fakeip_no_mapping_returns_none() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        // No FakeIP pool, no mapping recorded
        assert_eq!(resolver.reverse_lookup(&ip), None);
    }
}
