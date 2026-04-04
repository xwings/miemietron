use anyhow::Result;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::debug;

/// FakeIP pool: assigns fake IPs from a CIDR range to domains.
pub struct FakeIpPool {
    // Ring buffer state
    base: u32,         // Network address as u32
    size: u32,         // Number of usable addresses
    offset: AtomicU32, // Current position in ring

    // Bidirectional mappings
    ip_to_domain: DashMap<IpAddr, String>,
    domain_to_ip: DashMap<String, IpAddr>,

    // Filter
    filter: Vec<String>,
    filter_mode: FilterMode,
}

#[derive(Debug, Clone, PartialEq)]
enum FilterMode {
    Blacklist, // filter entries are NOT assigned fake IPs
    Whitelist, // only filter entries get fake IPs
}

impl FakeIpPool {
    pub fn new(cidr: &str, filter: &[String], filter_mode: &str) -> Result<Self> {
        let (base, prefix_len) = parse_cidr(cidr)?;
        let size = 1u32
            .checked_shl(32 - prefix_len)
            .unwrap_or(0)
            .saturating_sub(2); // exclude network + broadcast

        let mode = if filter_mode == "whitelist" {
            FilterMode::Whitelist
        } else {
            FilterMode::Blacklist
        };

        Ok(Self {
            base: base + 1, // Skip network address
            size,
            offset: AtomicU32::new(0),
            ip_to_domain: DashMap::new(),
            domain_to_ip: DashMap::new(),
            filter: filter.to_vec(),
            filter_mode: mode,
        })
    }

    /// Allocate a fake IP for a domain. Returns existing if already allocated.
    pub fn allocate(&self, domain: &str) -> IpAddr {
        // Check if domain already has a fake IP
        if let Some(ip) = self.domain_to_ip.get(domain) {
            return *ip;
        }

        // Allocate next IP from ring
        let idx = self.offset.fetch_add(1, Ordering::Relaxed) % self.size;
        let ip_u32 = self.base + idx;
        let ip = IpAddr::V4(Ipv4Addr::from(ip_u32));

        // Evict old mapping if this IP was previously assigned
        if let Some((_, old_domain)) = self.ip_to_domain.remove(&ip) {
            self.domain_to_ip.remove(&old_domain);
        }

        self.ip_to_domain.insert(ip, domain.to_string());
        self.domain_to_ip.insert(domain.to_string(), ip);

        ip
    }

    /// Look up the domain for a fake IP.
    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        self.ip_to_domain.get(ip).map(|v| v.value().clone())
    }

    /// Look up the fake IP for a domain.
    pub fn lookup_ip(&self, domain: &str) -> Option<IpAddr> {
        self.domain_to_ip.get(domain).map(|v| *v.value())
    }

    /// Check if an IP is within the fake IP range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(*v4);
                ip_u32 >= self.base && ip_u32 < self.base + self.size
            }
            _ => false,
        }
    }

    /// Check if a domain should bypass fake IP (i.e., is filtered).
    pub fn should_bypass(&self, domain: &str) -> bool {
        let matches_filter = self.filter.iter().any(|f| {
            if f.starts_with("*.") {
                let suffix = &f[1..]; // ".example.com"
                domain.ends_with(suffix) || domain == &f[2..]
            } else if let Some(suffix) = f.strip_prefix('+') {
                domain.ends_with(suffix)
            } else {
                domain == f
            }
        });

        match self.filter_mode {
            FilterMode::Blacklist => matches_filter,
            FilterMode::Whitelist => !matches_filter,
        }
    }

    /// Clear all mappings.
    pub fn clear(&self) {
        self.ip_to_domain.clear();
        self.domain_to_ip.clear();
        self.offset.store(0, Ordering::Relaxed);
    }

    pub fn size(&self) -> usize {
        self.ip_to_domain.len()
    }

    /// Save the current domain<->IP mappings to disk as JSON.
    ///
    /// Format: `{ "offset": N, "mappings": { "domain": "ip", ... } }`
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut mappings = std::collections::HashMap::new();
        for entry in self.domain_to_ip.iter() {
            mappings.insert(entry.key().clone(), entry.value().to_string());
        }
        let data = serde_json::json!({
            "offset": self.offset.load(Ordering::Relaxed),
            "mappings": mappings,
        });
        let json = serde_json::to_string(&data)?;
        // Write atomically via a temporary file
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes())?;
        std::fs::rename(&tmp_path, path)?;
        debug!(
            "FakeIP pool saved to {} ({} entries)",
            path.display(),
            mappings.len()
        );
        Ok(())
    }

    /// Load domain<->IP mappings from disk, restoring the pool state.
    ///
    /// Only loads mappings whose IPs fall within the current pool range.
    pub fn load(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            debug!("FakeIP persistence file not found, starting fresh");
            return Ok(());
        }

        let json = std::fs::read_to_string(path)?;
        let data: serde_json::Value = serde_json::from_str(&json)?;

        // Restore offset
        if let Some(offset) = data.get("offset").and_then(|v| v.as_u64()) {
            self.offset.store(offset as u32, Ordering::Relaxed);
        }

        // Restore mappings
        let mut loaded = 0u64;
        if let Some(mappings) = data.get("mappings").and_then(|v| v.as_object()) {
            for (domain, ip_str) in mappings {
                if let Some(ip_s) = ip_str.as_str() {
                    if let Ok(ip) = ip_s.parse::<IpAddr>() {
                        if self.contains(&ip) {
                            self.ip_to_domain.insert(ip, domain.clone());
                            self.domain_to_ip.insert(domain.clone(), ip);
                            loaded += 1;
                        }
                    }
                }
            }
        }

        debug!(
            "FakeIP pool loaded from {} ({} entries)",
            path.display(),
            loaded
        );
        Ok(())
    }
}

fn parse_cidr(cidr: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("invalid CIDR: {cidr}"));
    }
    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    let base = u32::from(ip);
    Ok((base, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool() -> FakeIpPool {
        // /24 gives 254 usable addresses (256 - network - broadcast)
        FakeIpPool::new("198.18.0.0/24", &[], "blacklist").unwrap()
    }

    #[test]
    fn allocate_ip_for_domain() {
        let pool = make_pool();
        let ip = pool.allocate("example.com");
        assert!(pool.contains(&ip));
    }

    #[test]
    fn reverse_lookup_works() {
        let pool = make_pool();
        let ip = pool.allocate("example.com");
        assert_eq!(pool.lookup_domain(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn same_domain_returns_same_ip() {
        let pool = make_pool();
        let ip1 = pool.allocate("example.com");
        let ip2 = pool.allocate("example.com");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn different_domains_get_different_ips() {
        let pool = make_pool();
        let ip1 = pool.allocate("a.com");
        let ip2 = pool.allocate("b.com");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn ring_buffer_wraps_around() {
        // Small pool: /30 gives 2 usable addresses
        let pool = FakeIpPool::new("10.0.0.0/30", &[], "blacklist").unwrap();
        let ip1 = pool.allocate("a.com");
        let ip2 = pool.allocate("b.com");
        // Third allocation wraps around and evicts the first
        let ip3 = pool.allocate("c.com");
        // ip3 should reuse ip1's slot
        assert_eq!(ip3, ip1);
        // "a.com" should have been evicted
        assert_eq!(pool.lookup_domain(&ip1), Some("c.com".to_string()));
        assert_eq!(pool.lookup_ip("a.com"), None);
        // "b.com" should still be there
        assert_eq!(pool.lookup_domain(&ip2), Some("b.com".to_string()));
    }

    #[test]
    fn contains_in_range() {
        let pool = make_pool();
        let in_range = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 100));
        let out_of_range = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(pool.contains(&in_range));
        assert!(!pool.contains(&out_of_range));
    }

    #[test]
    fn contains_ipv6_always_false() {
        let pool = make_pool();
        let ipv6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert!(!pool.contains(&ipv6));
    }

    #[test]
    fn blacklist_filter() {
        let filter = vec!["*.local".to_string(), "localhost".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("foo.local"));
        assert!(pool.should_bypass("localhost"));
        assert!(!pool.should_bypass("example.com"));
    }

    #[test]
    fn whitelist_filter() {
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "whitelist").unwrap();
        // Matches filter -> should NOT bypass (whitelist mode: only matched get fake IP)
        assert!(!pool.should_bypass("foo.example.com"));
        // Does not match filter -> should bypass
        assert!(pool.should_bypass("other.com"));
    }

    #[test]
    fn clear_resets_pool() {
        let pool = make_pool();
        pool.allocate("a.com");
        pool.allocate("b.com");
        assert_eq!(pool.size(), 2);
        pool.clear();
        assert_eq!(pool.size(), 0);
        assert_eq!(pool.lookup_ip("a.com"), None);
    }

    #[test]
    fn lookup_ip_works() {
        let pool = make_pool();
        let ip = pool.allocate("test.com");
        assert_eq!(pool.lookup_ip("test.com"), Some(ip));
        assert_eq!(pool.lookup_ip("nonexistent.com"), None);
    }

    // ---- Additional wildcard filter tests ----

    #[test]
    fn wildcard_filter_matches_subdomain() {
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("foo.example.com"));
        assert!(pool.should_bypass("bar.example.com"));
        assert!(pool.should_bypass("deep.sub.example.com"));
    }

    #[test]
    fn wildcard_filter_matches_exact_domain() {
        // *.example.com should also match "example.com" itself
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("example.com"));
    }

    #[test]
    fn wildcard_filter_does_not_match_partial() {
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        // "notexample.com" should NOT match *.example.com
        assert!(!pool.should_bypass("notexample.com"));
        assert!(!pool.should_bypass("other.com"));
    }

    #[test]
    fn wildcard_filter_star_lan() {
        let filter = vec!["*.lan".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("router.lan"));
        assert!(pool.should_bypass("nas.lan"));
        assert!(pool.should_bypass("lan")); // exact match
        assert!(!pool.should_bypass("lanmore.com"));
    }

    #[test]
    fn wildcard_filter_star_local() {
        let filter = vec!["*.local".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("myhost.local"));
        assert!(pool.should_bypass("local"));
        assert!(!pool.should_bypass("localhost")); // not a suffix match for .local
    }

    #[test]
    fn exact_filter_match() {
        let filter = vec!["dns.msftncsi.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("dns.msftncsi.com"));
        assert!(!pool.should_bypass("sub.dns.msftncsi.com"));
        assert!(!pool.should_bypass("other.com"));
    }

    #[test]
    fn plus_prefix_filter() {
        let filter = vec!["+.google.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("www.google.com"));
        assert!(pool.should_bypass("mail.google.com"));
        // "google.com" does NOT end with ".google.com" (the + prefix strips
        // only the '+', so the suffix becomes ".google.com" which is longer)
        assert!(!pool.should_bypass("google.com"));
    }

    // ---- Whitelist mode tests ----

    #[test]
    fn whitelist_only_matching_domains_get_fakeip() {
        let filter = vec!["*.example.com".to_string(), "specific.org".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "whitelist").unwrap();

        // Matches filter -> should NOT bypass (gets fake IP in whitelist mode)
        assert!(!pool.should_bypass("foo.example.com"));
        assert!(!pool.should_bypass("specific.org"));

        // Does NOT match filter -> should bypass (no fake IP)
        assert!(pool.should_bypass("google.com"));
        assert!(pool.should_bypass("random.org"));
        assert!(pool.should_bypass("other.specific.org"));
    }

    #[test]
    fn whitelist_empty_filter_bypasses_everything() {
        let pool = FakeIpPool::new("198.18.0.0/24", &[], "whitelist").unwrap();
        // With empty whitelist, nothing matches -> everything is bypassed
        assert!(pool.should_bypass("any.domain.com"));
        assert!(pool.should_bypass("example.com"));
    }

    #[test]
    fn blacklist_empty_filter_bypasses_nothing() {
        let pool = FakeIpPool::new("198.18.0.0/24", &[], "blacklist").unwrap();
        // With empty blacklist, nothing matches -> nothing is bypassed
        assert!(!pool.should_bypass("any.domain.com"));
        assert!(!pool.should_bypass("example.com"));
    }

    // ---- Multiple filters combined ----

    #[test]
    fn multiple_filters_blacklist() {
        let filter = vec![
            "*.lan".to_string(),
            "*.local".to_string(),
            "localhost".to_string(),
            "dns.msftncsi.com".to_string(),
        ];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(pool.should_bypass("router.lan"));
        assert!(pool.should_bypass("mypc.local"));
        assert!(pool.should_bypass("localhost"));
        assert!(pool.should_bypass("dns.msftncsi.com"));
        assert!(!pool.should_bypass("google.com"));
        assert!(!pool.should_bypass("example.com"));
    }

    // ---- Save/Load persistence ----

    #[test]
    fn save_and_load_round_trip() {
        let pool = make_pool();
        let ip1 = pool.allocate("a.com");
        let ip2 = pool.allocate("b.com");

        let tmp = std::env::temp_dir().join("fakeip_test.json");
        pool.save(&tmp).unwrap();

        // Create a new pool and load from the saved file
        let pool2 = make_pool();
        pool2.load(&tmp).unwrap();

        assert_eq!(pool2.lookup_domain(&ip1), Some("a.com".to_string()));
        assert_eq!(pool2.lookup_domain(&ip2), Some("b.com".to_string()));
        assert_eq!(pool2.lookup_ip("a.com"), Some(ip1));
        assert_eq!(pool2.lookup_ip("b.com"), Some(ip2));

        // Clean up
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_nonexistent_file_is_ok() {
        let pool = make_pool();
        let result = pool.load(Path::new("/tmp/nonexistent_fakeip_test_12345.json"));
        assert!(result.is_ok());
        assert_eq!(pool.size(), 0);
    }
}
