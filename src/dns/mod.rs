pub mod cache;
pub mod fakeip;
pub mod upstream;

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info};

use crate::config::DnsConfig;
use cache::DnsCache;
use fakeip::FakeIpPool;

pub struct DnsResolver {
    config: DnsConfig,
    cache: DnsCache,
    fakeip: Option<FakeIpPool>,
}

impl DnsResolver {
    pub async fn new(config: &DnsConfig) -> Result<Self> {
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

        Ok(Self {
            config: config.clone(),
            cache,
            fakeip,
        })
    }

    /// Resolve a domain name. In fake-ip mode, returns a fake IP.
    /// In redir-host mode, queries upstream DNS.
    pub async fn resolve(&self, domain: &str) -> Result<IpAddr> {
        // Check cache first
        if let Some(ip) = self.cache.get(domain) {
            return Ok(ip);
        }

        // FakeIP mode: assign a fake IP without upstream query
        if let Some(ref pool) = self.fakeip {
            let ip = pool.allocate(domain);
            self.cache.insert(domain.to_string(), ip);
            return Ok(ip);
        }

        // Redir-host mode: query upstream
        let ip = self.query_upstream(domain).await?;
        self.cache.insert(domain.to_string(), ip);
        Ok(ip)
    }

    /// Reverse-lookup: given a (fake) IP, return the original domain.
    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<String> {
        if let Some(ref pool) = self.fakeip {
            return pool.lookup_domain(ip);
        }
        None
    }

    /// Query upstream DNS servers for a real IP.
    pub async fn query_upstream(&self, domain: &str) -> Result<IpAddr> {
        upstream::resolve(domain, &self.config).await
    }

    /// Check if an IP is in the fake IP range.
    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        if let Some(ref pool) = self.fakeip {
            return pool.contains(ip);
        }
        false
    }

    /// Flush the DNS cache.
    pub fn flush_cache(&self) {
        self.cache.clear();
    }

    /// Flush the FakeIP pool.
    pub fn flush_fakeip(&self) {
        if let Some(ref pool) = self.fakeip {
            pool.clear();
        }
    }
}

/// Run a DNS server that listens for queries and responds using the resolver.
pub async fn run_dns_server(listen: &str, resolver: Arc<DnsResolver>) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1053));

    let socket = UdpSocket::bind(addr).await?;
    info!("DNS server listening on {}", addr);

    let mut buf = vec![0u8; 512];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!("DNS recv error: {}", e);
                continue;
            }
        };

        let data = buf[..n].to_vec();
        let resolver = resolver.clone();

        // Parse DNS query and respond
        // For now, we do a basic implementation
        // Full DNS wire format parsing comes in Phase 2
        match parse_dns_query(&data) {
            Some((id, domain, qtype)) => {
                debug!("DNS query: {} (type {})", domain, qtype);
                match resolver.resolve(&domain).await {
                    Ok(ip) => {
                        let response = build_dns_response(id, &domain, ip);
                        let _ = socket.send_to(&response, src).await;
                    }
                    Err(e) => {
                        debug!("DNS resolve failed for {}: {}", domain, e);
                        // Send SERVFAIL
                        let response = build_dns_servfail(id);
                        let _ = socket.send_to(&response, src).await;
                    }
                }
            }
            None => {
                debug!("Failed to parse DNS query");
            }
        }
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

/// Build a minimal DNS response with an A record.
fn build_dns_response(id: u16, domain: &str, ip: IpAddr) -> Vec<u8> {
    let mut response = Vec::with_capacity(128);

    // Header
    response.extend_from_slice(&id.to_be_bytes()); // ID
    response.extend_from_slice(&[0x81, 0x80]); // Flags: response, recursion desired+available
    response.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    response.extend_from_slice(&[0x00, 0x01]); // Answers: 1
    response.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    response.extend_from_slice(&[0x00, 0x00]); // Additional: 0

    // Question section (echo back)
    for part in domain.split('.') {
        response.push(part.len() as u8);
        response.extend_from_slice(part.as_bytes());
    }
    response.push(0); // End of domain

    match ip {
        IpAddr::V4(_) => {
            response.extend_from_slice(&[0x00, 0x01]); // Type A
            response.extend_from_slice(&[0x00, 0x01]); // Class IN
        }
        IpAddr::V6(_) => {
            response.extend_from_slice(&[0x00, 0x1c]); // Type AAAA
            response.extend_from_slice(&[0x00, 0x01]); // Class IN
        }
    }

    // Answer section
    response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to question

    match ip {
        IpAddr::V4(ipv4) => {
            response.extend_from_slice(&[0x00, 0x01]); // Type A
            response.extend_from_slice(&[0x00, 0x01]); // Class IN
            response.extend_from_slice(&3600u32.to_be_bytes()); // TTL
            response.extend_from_slice(&[0x00, 0x04]); // Data length
            response.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            response.extend_from_slice(&[0x00, 0x1c]); // Type AAAA
            response.extend_from_slice(&[0x00, 0x01]); // Class IN
            response.extend_from_slice(&3600u32.to_be_bytes()); // TTL
            response.extend_from_slice(&[0x00, 0x10]); // Data length
            response.extend_from_slice(&ipv6.octets());
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
