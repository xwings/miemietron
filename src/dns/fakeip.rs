use anyhow::Result;
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::debug;

/// Pre-compiled filter for fast domain bypass checks.
/// Separates exact matches (O(1) HashSet lookup) from suffix patterns.
struct CompiledFilter {
    /// Exact domain matches (from bare patterns and `*.domain` patterns).
    exact: HashSet<String>,
    /// Suffix patterns to check with ends_with (from `*.` and `+` patterns).
    suffixes: Vec<String>,
}

/// FakeIP pool: assigns fake IPs from a CIDR range to domains.
pub struct FakeIpPool {
    // Ring buffer state
    base: u32,         // First allocatable IP as u32 (network + 4)
    size: u32,         // Number of allocatable addresses
    offset: AtomicU32, // Current position in ring

    // Full CIDR range for `contains()` / `is_fake_ip()` checks
    cidr_base: u32, // Network address of the CIDR
    cidr_size: u32, // Total number of IPs in the CIDR

    // Bidirectional mappings
    ip_to_domain: DashMap<IpAddr, String>,
    domain_to_ip: DashMap<String, IpAddr>,

    // Filter (pre-compiled for fast matching)
    compiled_filter: CompiledFilter,
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
        let total = 1u32.checked_shl(32 - prefix_len).unwrap_or(0);

        // mihomo compat: first allocatable IP is base+4 (skip .0 network,
        // .1 gateway, .2 and .3 reserved); the broadcast address (last IP of
        // the prefix) is never allocated (pool.go: offset cycles before
        // reaching `last`).
        // Checked arithmetic: degenerate ranges (/0 makes `total` overflow to
        // 0 above) fall through to the "too small" error instead of wrapping.
        let first = base.saturating_add(4);
        let last = total
            .checked_sub(1)
            .and_then(|t| base.checked_add(t))
            .unwrap_or(0); // broadcast — excluded from allocation
        if first >= last {
            return Err(anyhow::anyhow!(
                "fake-ip-range {cidr} is too small (need at least /29, got /{prefix_len})"
            ));
        }
        let size = last - first; // number of usable addresses

        let mode = if filter_mode == "whitelist" {
            FilterMode::Whitelist
        } else {
            FilterMode::Blacklist
        };

        // Pre-compile filter patterns into exact matches and suffix lists
        // for O(1) exact lookups instead of O(n) iteration per query.
        let mut exact = HashSet::with_capacity(filter.len());
        let mut suffixes = Vec::new();
        for f in filter {
            if let Some(stripped) = f.strip_prefix("*.") {
                // *.example.com → suffix ".example.com" + exact "example.com"
                suffixes.push(format!(".{stripped}"));
                exact.insert(stripped.to_string());
            } else if let Some(suffix) = f.strip_prefix('+') {
                suffixes.push(suffix.to_string());
            } else {
                exact.insert(f.clone());
            }
        }
        let compiled_filter = CompiledFilter { exact, suffixes };

        Ok(Self {
            base: first, // First allocatable IP (base+4)
            size,
            cidr_base: base,
            cidr_size: total,
            offset: AtomicU32::new(0),
            ip_to_domain: DashMap::new(),
            domain_to_ip: DashMap::new(),
            compiled_filter,
            filter_mode: mode,
        })
    }

    /// Allocate a fake IP for a domain. Returns existing if already allocated.
    /// mihomo compat: pool.go lowercases the host (RFC 4343) so DNS 0x20 case
    /// randomization can't allocate distinct fake IPs per casing.
    pub fn allocate(&self, domain: &str) -> IpAddr {
        let domain = domain.to_lowercase();
        let domain = domain.as_str();
        // Check if domain already has a fake IP
        if let Some(ip) = self.domain_to_ip.get(domain) {
            return *ip;
        }

        // Allocate the next IP from the ring buffer: the offset advances
        // monotonically and wraps modulo the pool size, and whatever mapping
        // currently occupies the slot is evicted unconditionally. With a
        // typical /16 pool the ring takes ~65k allocations to wrap, so
        // evicting a still-active mapping is rare in practice.
        let start = self.offset.fetch_add(1, Ordering::Relaxed);
        let idx = start % self.size;
        let ip_u32 = self.base + idx;
        let ip = IpAddr::V4(Ipv4Addr::from(ip_u32));

        // Evict old mapping for this IP slot
        if let Some((_, old_domain)) = self.ip_to_domain.remove(&ip) {
            self.domain_to_ip.remove(&old_domain);
        }

        self.ip_to_domain.insert(ip, domain.to_string());
        self.domain_to_ip.insert(domain.to_string(), ip);

        debug!(
            "FakeIP: allocated {} for {} (pool usage: {}/{})",
            ip,
            domain,
            self.ip_to_domain.len(),
            self.size
        );

        ip
    }

    /// Look up the domain for a fake IP.
    pub fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        self.ip_to_domain.get(ip).map(|v| v.value().clone())
    }

    /// Check if an IP is within the full fake IP CIDR range.
    /// This covers the entire prefix including gateway and reserved addresses.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(*v4);
                ip_u32 >= self.cidr_base && ip_u32 < self.cidr_base + self.cidr_size
            }
            _ => false,
        }
    }

    /// mihomo compat: enhancer.go IsFakeIP — inside the range but NOT the
    /// gateway (base+1, the TUN device address) or the broadcast address.
    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(*v4);
                self.contains(ip)
                    && ip_u32 != self.cidr_base + 1
                    && ip_u32 != self.cidr_base + self.cidr_size - 1
            }
            _ => false,
        }
    }

    /// Raw filter-pattern match (no filter-mode applied). The resolver ORs
    /// this with the geosite/rule-set checkers before applying the mode.
    pub fn filter_matches(&self, domain: &str) -> bool {
        self.compiled_filter.exact.contains(domain)
            || self
                .compiled_filter
                .suffixes
                .iter()
                .any(|s| domain.ends_with(s.as_str()))
    }

    /// Whether fake-ip-filter-mode is whitelist.
    pub fn is_whitelist(&self) -> bool {
        self.filter_mode == FilterMode::Whitelist
    }

    /// Clear all mappings.
    pub fn clear(&self) {
        self.ip_to_domain.clear();
        self.domain_to_ip.clear();
        self.offset.store(0, Ordering::Relaxed);
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
    if prefix_len > 32 {
        return Err(anyhow::anyhow!("invalid CIDR: {cidr}"));
    }

    // Normalize to network address: mask off host bits.
    // mihomo configs often use "198.18.0.1/16" instead of "198.18.0.0/16".
    let raw = u32::from(ip);
    let mask = (!0u32).checked_shl(32 - prefix_len).unwrap_or(0);
    let base = raw & mask;
    Ok((base, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of `DnsResolver::should_bypass_fakeip`'s mode application for
    /// the pattern-only case — the production path lives in `dns/mod.rs` and
    /// additionally ORs in the geosite/rule-set checkers before applying the
    /// filter mode.
    fn should_bypass(pool: &FakeIpPool, domain: &str) -> bool {
        let matched = pool.filter_matches(domain);
        if pool.is_whitelist() {
            !matched
        } else {
            matched
        }
    }

    fn make_pool() -> FakeIpPool {
        // mihomo compat: /24 gives 252 usable addresses (256 - 4 reserved)
        // First allocatable: 198.18.0.4, last: 198.18.0.255
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
        // mihomo compat: /29 gives 3 usable addresses (.4, .5, .6) — .7 is
        // the broadcast address, which pool.go never allocates.
        let pool = FakeIpPool::new("10.0.0.0/29", &[], "blacklist").unwrap();
        let ip1 = pool.allocate("a.com");
        let ip2 = pool.allocate("b.com");
        let ip3 = pool.allocate("c.com");
        assert_ne!(ip3, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
        // Fourth allocation wraps around and evicts the first
        let ip4 = pool.allocate("d.com");
        assert_eq!(ip4, ip1);
        assert_eq!(pool.lookup_domain(&ip1), Some("d.com".to_string()));
        // Others should still be there
        assert_eq!(pool.lookup_domain(&ip2), Some("b.com".to_string()));
        assert_eq!(pool.lookup_domain(&ip3), Some("c.com".to_string()));
    }

    #[test]
    fn too_small_cidr_rejected() {
        // mihomo compat: /30 (4 IPs) is too small — first=base+4 > last=base+3
        assert!(FakeIpPool::new("10.0.0.0/30", &[], "blacklist").is_err());
        assert!(FakeIpPool::new("10.0.0.0/31", &[], "blacklist").is_err());
        assert!(FakeIpPool::new("10.0.0.0/32", &[], "blacklist").is_err());
        // /29 (8 IPs) is the minimum — 3 usable (.4-.6; .7 is broadcast)
        assert!(FakeIpPool::new("10.0.0.0/29", &[], "blacklist").is_ok());
    }

    #[test]
    fn oversized_prefix_rejected() {
        // /33 must be rejected by parse_cidr, not underflow 32 - prefix_len
        assert!(FakeIpPool::new("10.0.0.0/33", &[], "blacklist").is_err());
        assert!(FakeIpPool::new("10.0.0.0/128", &[], "blacklist").is_err());
    }

    #[test]
    fn zero_prefix_rejected() {
        // /0 makes the pool-size computation degenerate — must error, not wrap
        assert!(FakeIpPool::new("0.0.0.0/0", &[], "blacklist").is_err());
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
        assert!(should_bypass(&pool, "foo.local"));
        assert!(should_bypass(&pool, "localhost"));
        assert!(!should_bypass(&pool, "example.com"));
    }

    #[test]
    fn whitelist_filter() {
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "whitelist").unwrap();
        // Matches filter -> should NOT bypass (whitelist mode: only matched get fake IP)
        assert!(!should_bypass(&pool, "foo.example.com"));
        // Does not match filter -> should bypass
        assert!(should_bypass(&pool, "other.com"));
    }

    #[test]
    fn clear_resets_pool() {
        let pool = make_pool();
        let ip_a = pool.allocate("a.com");
        pool.allocate("b.com");
        pool.clear();
        assert_eq!(pool.lookup_domain(&ip_a), None);
    }

    #[test]
    fn wildcard_filter_matches_subdomain() {
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "foo.example.com"));
        assert!(should_bypass(&pool, "bar.example.com"));
        assert!(should_bypass(&pool, "deep.sub.example.com"));
    }

    #[test]
    fn wildcard_filter_matches_exact_domain() {
        // *.example.com should also match "example.com" itself
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "example.com"));
    }

    #[test]
    fn wildcard_filter_does_not_match_partial() {
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        // "notexample.com" should NOT match *.example.com
        assert!(!should_bypass(&pool, "notexample.com"));
        assert!(!should_bypass(&pool, "other.com"));
    }

    #[test]
    fn wildcard_filter_star_lan() {
        let filter = vec!["*.lan".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "router.lan"));
        assert!(should_bypass(&pool, "nas.lan"));
        assert!(should_bypass(&pool, "lan")); // exact match
        assert!(!should_bypass(&pool, "lanmore.com"));
    }

    #[test]
    fn wildcard_filter_star_local() {
        let filter = vec!["*.local".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "myhost.local"));
        assert!(should_bypass(&pool, "local"));
        assert!(!should_bypass(&pool, "localhost")); // not a suffix match for .local
    }

    #[test]
    fn exact_filter_match() {
        let filter = vec!["dns.msftncsi.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "dns.msftncsi.com"));
        assert!(!should_bypass(&pool, "sub.dns.msftncsi.com"));
        assert!(!should_bypass(&pool, "other.com"));
    }

    #[test]
    fn plus_prefix_filter() {
        let filter = vec!["+.google.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "www.google.com"));
        assert!(should_bypass(&pool, "mail.google.com"));
        // "google.com" does NOT end with ".google.com" (the + prefix strips
        // only the '+', so the suffix becomes ".google.com" which is longer)
        assert!(!should_bypass(&pool, "google.com"));
    }

    #[test]
    fn whitelist_only_matching_domains_get_fakeip() {
        let filter = vec!["*.example.com".to_string(), "specific.org".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "whitelist").unwrap();

        // Matches filter -> should NOT bypass (gets fake IP in whitelist mode)
        assert!(!should_bypass(&pool, "foo.example.com"));
        assert!(!should_bypass(&pool, "specific.org"));

        // Does NOT match filter -> should bypass (no fake IP)
        assert!(should_bypass(&pool, "google.com"));
        assert!(should_bypass(&pool, "random.org"));
        assert!(should_bypass(&pool, "other.specific.org"));
    }

    #[test]
    fn whitelist_empty_filter_bypasses_everything() {
        let pool = FakeIpPool::new("198.18.0.0/24", &[], "whitelist").unwrap();
        // With empty whitelist, nothing matches -> everything is bypassed
        assert!(should_bypass(&pool, "any.domain.com"));
        assert!(should_bypass(&pool, "example.com"));
    }

    #[test]
    fn blacklist_empty_filter_bypasses_nothing() {
        let pool = FakeIpPool::new("198.18.0.0/24", &[], "blacklist").unwrap();
        // With empty blacklist, nothing matches -> nothing is bypassed
        assert!(!should_bypass(&pool, "any.domain.com"));
        assert!(!should_bypass(&pool, "example.com"));
    }

    #[test]
    fn multiple_filters_blacklist() {
        let filter = vec![
            "*.lan".to_string(),
            "*.local".to_string(),
            "localhost".to_string(),
            "dns.msftncsi.com".to_string(),
        ];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "router.lan"));
        assert!(should_bypass(&pool, "mypc.local"));
        assert!(should_bypass(&pool, "localhost"));
        assert!(should_bypass(&pool, "dns.msftncsi.com"));
        assert!(!should_bypass(&pool, "google.com"));
        assert!(!should_bypass(&pool, "example.com"));
    }

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

        // Clean up
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_nonexistent_file_is_ok() {
        let pool = make_pool();
        let result = pool.load(Path::new("/tmp/nonexistent_fakeip_test_12345.json"));
        assert!(result.is_ok());
    }
}
