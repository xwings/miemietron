use anyhow::Result;
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::debug;

/// One `fake-ip-filter` entry.
///
/// mihomo compat: config/config.go parseDomain — the `geosite:` / `rule-set:`
/// prefix is tested case-insensitively and the names are what sits between
/// the first and the second `:`, split at `,` (`geosite:cn,private`). Every
/// other entry is a domain pattern.
pub(super) enum FilterEntry<'a> {
    Geosite(Vec<&'a str>),
    RuleSet(Vec<&'a str>),
    Domain(&'a str),
}

impl<'a> FilterEntry<'a> {
    pub(super) fn parse(entry: &'a str) -> Self {
        let has_prefix = |prefix: &str| {
            entry
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        };
        let names = || {
            entry
                .split(':')
                .nth(1)
                .unwrap_or_default()
                .split(',')
                .collect()
        };
        if has_prefix("geosite:") {
            Self::Geosite(names())
        } else if has_prefix("rule-set:") {
            Self::RuleSet(names())
        } else {
            Self::Domain(entry)
        }
    }
}

/// Label of the node standing for any non-empty run of further labels.
const SUBDOMAINS: &str = "+";
/// Label of the node standing for exactly one label.
const ANY_LABEL: &str = "*";

/// Domain patterns matched label by label, with the semantics of mihomo's
/// `trie.DomainSet` (component/trie/domain.go, domain_set.go):
/// - names compare case-insensitively;
/// - `*` stands for exactly one label, wherever it sits (`time.*.com`);
/// - a leading `+.` matches the rest of the pattern and every subdomain of it;
/// - a leading `.` matches subdomains only.
#[derive(Default)]
struct DomainSet {
    /// Child nodes by label, walked from the top-level label down.
    children: HashMap<String, DomainSet>,
    /// A pattern ends at this node.
    terminal: bool,
}

impl DomainSet {
    /// mihomo compat: domain_set.go DomainSetBuilder.Insert.
    fn insert(&mut self, pattern: &str) -> Result<()> {
        let mut labels = valid_and_split_domain(pattern)?;
        if labels[0] == SUBDOMAINS {
            self.insert_labels(&labels[1..]);
        } else if labels[0].is_empty() {
            labels[0] = SUBDOMAINS.to_string();
        }
        self.insert_labels(&labels);
        Ok(())
    }

    fn insert_labels(&mut self, labels: &[String]) {
        let mut node = self;
        for label in labels.iter().rev() {
            node = node.children.entry(label.clone()).or_default();
        }
        node.terminal = true;
    }

    /// mihomo compat: domain_set.go Has.
    fn has(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let labels: Vec<&str> = domain.split('.').collect();
        self.matches(&labels)
    }

    fn matches(&self, labels: &[&str]) -> bool {
        let Some((label, rest)) = labels.split_last() else {
            return self.terminal;
        };
        // An empty leftmost label (the empty name, a leading dot) leaves
        // nothing for a wildcard to stand for.
        let wildcard_fits = !(rest.is_empty() && label.is_empty());
        if wildcard_fits && self.children.contains_key(SUBDOMAINS) {
            return true;
        }
        self.children
            .get(*label)
            .is_some_and(|node| node.matches(rest))
            || (wildcard_fits
                && self
                    .children
                    .get(ANY_LABEL)
                    .is_some_and(|node| node.matches(rest)))
    }
}

/// Lower-case a domain pattern and split it into labels, rejecting a
/// malformed one.
///
/// mihomo compat: component/trie/domain.go ValidAndSplitDomain, error texts
/// included.
fn valid_and_split_domain(domain: &str) -> Result<Vec<String>> {
    let invalid = |reason: String| anyhow::anyhow!("invalid domain {domain:?}: {reason}");
    if domain.is_empty() {
        return Err(invalid("domain is empty".into()));
    }
    if domain.ends_with('.') {
        return Err(invalid("trailing dot is not allowed".into()));
    }
    if domain.starts_with(char::is_whitespace) {
        return Err(invalid("leading whitespace is not allowed".into()));
    }
    if domain.ends_with(char::is_whitespace) {
        return Err(invalid("trailing whitespace is not allowed".into()));
    }

    let labels: Vec<String> = domain
        .to_lowercase()
        .split('.')
        .map(str::to_string)
        .collect();
    // An empty first label is the ".example.com" form; any other is a typo.
    if let Some(i) = labels.iter().skip(1).position(String::is_empty) {
        return Err(invalid(format!("label {} is empty", i + 2)));
    }
    for (i, label) in labels.iter().enumerate() {
        if label.contains('+') {
            if label != "+" {
                return Err(invalid(format!(
                    "\"+\" wildcard must occupy the entire label {}",
                    i + 1
                )));
            }
            if i != 0 {
                return Err(invalid(
                    "\"+\" wildcard is only allowed in the first label".into(),
                ));
            }
            if labels.len() == 1 {
                return Err(invalid(
                    "\"+\" wildcard must be followed by another label".into(),
                ));
            }
        }
        if label.contains('*') && label != "*" {
            return Err(invalid(format!(
                "\"*\" wildcard must occupy the entire label {}",
                i + 1
            )));
        }
    }
    Ok(labels)
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

    // Domain patterns of the filter
    filter: DomainSet,
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

        // mihomo compat: config.go parseDomain — the `geosite:` / `rule-set:`
        // entries belong to the resolver's checkers; an invalid pattern fails
        // the config load. With `fake-ip-filter-mode: rule` (unsupported) the
        // entries are rule lines, not patterns (config.go parseFakeIPRules).
        let mut domains = DomainSet::default();
        if !filter_mode.eq_ignore_ascii_case("rule") {
            for (idx, entry) in filter.iter().enumerate() {
                if let FilterEntry::Domain(pattern) = FilterEntry::parse(entry) {
                    domains
                        .insert(pattern)
                        .map_err(|e| anyhow::anyhow!("dns.fake-ip-filter[{idx}]: {e}"))?;
                }
            }
        }

        Ok(Self {
            base: first, // First allocatable IP (base+4)
            size,
            cidr_base: base,
            cidr_size: total,
            offset: AtomicU32::new(0),
            ip_to_domain: DashMap::new(),
            domain_to_ip: DashMap::new(),
            filter: domains,
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
        self.filter.has(domain)
    }

    /// Whether fake-ip-filter-mode is whitelist.
    pub fn is_whitelist(&self) -> bool {
        self.filter_mode == FilterMode::Whitelist
    }

    /// Carry all mappings over from the pool of the previous config.
    ///
    /// mihomo compat: pool.go `CloneFrom` (called from `PatchFrom` in
    /// dns/enhancer.go on every config reload) — LruCache.CloneTo overwrites
    /// the target store, so clear first, then copy both directions blindly
    /// (mihomo does not re-validate entries against the new range either).
    /// The ring offset is also carried: mihomo's cachefile store restores it
    /// via restoreState, while its memory store restarts from the first IP
    /// and immediately re-walks slots still held by the cloned mappings —
    /// we deliberately keep the offset in both modes to avoid that reuse.
    pub fn clone_from(&self, old: &FakeIpPool) {
        self.ip_to_domain.clear();
        self.domain_to_ip.clear();
        for entry in old.ip_to_domain.iter() {
            self.ip_to_domain
                .insert(*entry.key(), entry.value().clone());
        }
        for entry in old.domain_to_ip.iter() {
            self.domain_to_ip
                .insert(entry.key().clone(), *entry.value());
        }
        self.offset
            .store(old.offset.load(Ordering::Relaxed), Ordering::Relaxed);
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
        // mihomo compat: `*` is exactly one label (trie/domain_test.go
        // TestTrie_Wildcard: `*.example.com` does not find foo.sub.example.com).
        assert!(!should_bypass(&pool, "deep.sub.example.com"));
    }

    #[test]
    fn wildcard_filter_does_not_match_apex() {
        // mihomo compat: trie/domain_test.go TestTrie_Wildcard — with
        // `*.example.com` inserted, Search("example.com") is nil.
        let filter = vec!["*.example.com".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(!should_bypass(&pool, "example.com"));
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
        // mihomo compat: trie/domain_test.go TestTrie_Boundary — `*.dev`
        // does not find "dev".
        assert!(!should_bypass(&pool, "lan"));
        assert!(!should_bypass(&pool, "lanmore.com"));
    }

    #[test]
    fn wildcard_filter_star_local() {
        let filter = vec!["*.local".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "myhost.local"));
        assert!(!should_bypass(&pool, "local")); // TestTrie_Boundary, as above
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
        // mihomo compat: `+.` covers the domain itself as well
        // (trie/domain_set_test.go TestDomainSet: `+.cn` has "cn").
        assert!(should_bypass(&pool, "google.com"));
    }

    /// The match tables of mihomo's own trie tests
    /// (component/trie/domain_set_test.go, domain_test.go).
    #[test]
    fn domain_set_matches_like_mihomo() {
        // (patterns, names that match, names that do not)
        let long_labels = "label.".repeat(50);
        let long_hit = format!("{long_labels}example.com");
        let long_miss = format!("{long_labels}example.net");
        let cases: &[(&[&str], &[&str], &[&str])] = &[
            // TestDomainSet
            (
                &[
                    "baidu.com",
                    "google.com",
                    "www.google.com",
                    "test.a.net",
                    "test.a.oc",
                    "Mijia Cloud",
                    ".qq.com",
                    "+.cn",
                ],
                &[
                    "test.cn",
                    "cn",
                    "Mijia Cloud",
                    "test.a.net",
                    "www.qq.com",
                    "google.com",
                ],
                &["qq.com", "www.baidu.com"],
            ),
            // TestDomainSetForeach
            (
                &[".example.com", "+.example.org", "example.net"],
                &[
                    "www.example.com",
                    "example.org",
                    "www.example.org",
                    "example.net",
                ],
                &["example.com", "www.example.net"],
            ),
            // TestDomainSetComplexWildcard
            (
                &[
                    "+.baidu.com",
                    "+.a.baidu.com",
                    "www.baidu.com",
                    "+.bb.baidu.com",
                    "test.a.net",
                    "test.a.oc",
                    "www.qq.com",
                ],
                &["www.baidu.com", "test.test.baidu.com"],
                &["google.com"],
            ),
            // TestDomainSetWildcard
            (
                &[
                    "*.*.*.baidu.com",
                    "www.baidu.*",
                    "stun.*.*",
                    "*.*.qq.com",
                    "test.*.baidu.com",
                    "*.apple.com",
                ],
                &[
                    "www.baidu.com",
                    "test.test.baidu.com",
                    "test.test.qq.com",
                    "stun.ab.cd",
                ],
                &[
                    "test.baidu.com",
                    "www.google.com",
                    "a.www.google.com",
                    "test.qq.com",
                    "test.test.test.qq.com",
                ],
            ),
            // TestDomainSetWildcardShadow
            (
                &["*.example.com", "dead.a.example.com"],
                &["a.example.com"],
                &["b.a.example.com"],
            ),
            (
                &[
                    "*.*.example.com",
                    "dead.*.a.example.com",
                    "dead.b.a.example.com",
                ],
                &["b.a.example.com"],
                &["a.example.com"],
            ),
            (
                &["*.*.*.example.com", "*.a.example.com"],
                &["b.c.a.example.com"],
                &["d.b.c.a.example.com"],
            ),
            // TestDomainSetCase
            (
                &["example.com", "EXAMPLE.COM", "+.mixed.example.org"],
                &["EXAMPLE.COM", "ExAmPlE.cOm", "WWW.MIXED.EXAMPLE.ORG"],
                &["EXAMPLE.NET"],
            ),
            // TestDomainSetUnicode
            (
                &["中文.example", "+.测试.cn"],
                &["中文.example", "www.测试.cn"],
                &["日本語.example"],
            ),
            // TestDomainSetOversizedKey
            (
                &["+.example.com"],
                &[long_hit.as_str()],
                &[long_miss.as_str()],
            ),
            // TestTrie_Wildcard
            (
                &[
                    "*.example.com",
                    "sub.*.example.com",
                    "*.dev",
                    ".org",
                    ".example.net",
                    ".apple.*",
                    "+.foo.com",
                    "+.stun.*.*",
                    "+.stun.*.*.*",
                    "+.stun.*.*.*.*",
                    "stun.l.google.com",
                ],
                &[
                    "sub.example.com",
                    "sub.foo.example.com",
                    "test.org",
                    "test.example.net",
                    "test.apple.com",
                    "test.foo.com",
                    "foo.com",
                    "global.stun.website.com",
                ],
                &["foo.sub.example.com", "foo.example.dev", "example.com"],
            ),
            // TestTrie_Boundary
            (&["*.dev"], &[], &["dev"]),
            // TestTrie_WildcardBoundary
            (&["+.*", "stun.*.*.*"], &["example.com"], &[]),
            // TestTrie_InvalidWildcardPlacement, consistency: a lone `*` is
            // any single-label name.
            (&["*"], &["com"], &["example.com"]),
            // Not in mihomo's tables, read off domain_set.go Has: a wildcard
            // never stands for an empty leftmost label.
            (
                &["*", "+.example.com", "*.example.org"],
                &[],
                &["", ".example.com", ".example.org"],
            ),
        ];
        for (patterns, hits, misses) in cases {
            let mut set = DomainSet::default();
            for pattern in *patterns {
                set.insert(pattern).unwrap();
            }
            for name in *hits {
                assert!(set.has(name), "{patterns:?} should match {name:?}");
            }
            for name in *misses {
                assert!(!set.has(name), "{patterns:?} should not match {name:?}");
            }
        }
    }

    /// mihomo compat: component/trie/domain_test.go
    /// TestTrie_InvalidWildcardPlacement, TestTrie_ValidAndSplitDomain and
    /// TestTrie_Boundary — the rejected patterns and why.
    #[test]
    fn invalid_patterns_are_rejected_like_mihomo() {
        for valid in [
            "+.example.com",
            "*.example.com",
            "+.*",
            "stun.*.*.*",
            "*",
            "a.*",
            "*.a",
        ] {
            assert!(
                valid_and_split_domain(valid).is_ok(),
                "should accept {valid:?}"
            );
        }
        assert_eq!(
            valid_and_split_domain("GOOGLE.COM").unwrap(),
            ["google", "com"]
        );
        assert_eq!(
            valid_and_split_domain("Mijia Cloud").unwrap(),
            ["mijia cloud"]
        );

        for (domain, reason) in [
            (
                "stun.+",
                "\"+\" wildcard is only allowed in the first label",
            ),
            ("a.+.b", "\"+\" wildcard is only allowed in the first label"),
            ("a.+", "\"+\" wildcard is only allowed in the first label"),
            ("+", "\"+\" wildcard must be followed by another label"),
            (
                "+.+.com",
                "\"+\" wildcard is only allowed in the first label",
            ),
            ("a+b.com", "\"+\" wildcard must occupy the entire label 1"),
            ("a*b.com", "\"*\" wildcard must occupy the entire label 1"),
            ("*a.com", "\"*\" wildcard must occupy the entire label 1"),
            ("a*.com", "\"*\" wildcard must occupy the entire label 1"),
            ("", "domain is empty"),
            ("example.com.", "trailing dot is not allowed"),
            (".", "trailing dot is not allowed"),
            (" example.com", "leading whitespace is not allowed"),
            ("example.com ", "trailing whitespace is not allowed"),
            ("A..COM", "label 2 is empty"),
            ("..dev", "label 2 is empty"),
        ] {
            let err = valid_and_split_domain(domain).unwrap_err().to_string();
            assert_eq!(err, format!("invalid domain {domain:?}: {reason}"));
        }
    }

    /// mihomo compat: config.go parseDomain — an invalid fake-ip-filter
    /// pattern fails the config load, naming the entry.
    #[test]
    fn invalid_filter_pattern_fails_pool_construction() {
        let filter = vec![
            "*.lan".to_string(),
            "geosite:cn".to_string(),
            "time.*.com.".to_string(),
        ];
        let err = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist")
            .err()
            .expect("a trailing dot is not a valid pattern")
            .to_string();
        assert_eq!(
            err,
            "dns.fake-ip-filter[2]: invalid domain \"time.*.com.\": trailing dot is not allowed"
        );
    }

    /// mihomo compat: config.go parseDomain — `geosite:` / `rule-set:` are
    /// recognised in any case and name comma-separated lists; such entries
    /// are no domain patterns.
    #[test]
    fn filter_entry_prefixes_and_comma_lists() {
        let names = |entry| match FilterEntry::parse(entry) {
            FilterEntry::Geosite(names) => ("geosite", names),
            FilterEntry::RuleSet(names) => ("rule-set", names),
            FilterEntry::Domain(pattern) => ("domain", vec![pattern]),
        };
        assert_eq!(names("geosite:cn"), ("geosite", vec!["cn"]));
        assert_eq!(
            names("GEOSITE:cn,private"),
            ("geosite", vec!["cn", "private"])
        );
        assert_eq!(names("Rule-Set:a,B"), ("rule-set", vec!["a", "B"]));
        assert_eq!(
            names("geosite.example.com"),
            ("domain", vec!["geosite.example.com"])
        );

        // A `+` in a rule-set name is no pattern error: the entry never
        // reaches the domain set.
        let filter = vec!["rule-set:cn+private".to_string(), "+.lan".to_string()];
        let pool = FakeIpPool::new("198.18.0.0/24", &filter, "blacklist").unwrap();
        assert!(should_bypass(&pool, "router.lan"));
        assert!(!should_bypass(&pool, "rule-set:cn+private"));
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
    fn clone_from_preserves_mappings_across_reload() {
        let old = make_pool();
        let ip_a = old.allocate("a.com");
        let ip_b = old.allocate("b.com");

        let new = make_pool();
        new.clone_from(&old);

        // Existing domains keep their fake IPs
        assert_eq!(new.allocate("a.com"), ip_a);
        assert_eq!(new.allocate("b.com"), ip_b);
        assert_eq!(new.lookup_domain(&ip_a), Some("a.com".to_string()));
        assert_eq!(new.lookup_domain(&ip_b), Some("b.com".to_string()));
    }

    #[test]
    fn clone_from_carries_offset_so_new_domains_do_not_collide() {
        let old = make_pool();
        let ip_a = old.allocate("a.com");
        let ip_b = old.allocate("b.com");

        let new = make_pool();
        new.clone_from(&old);

        // A new domain must NOT steal a.com's or b.com's slot
        let ip_c = new.allocate("c.com");
        assert_ne!(ip_c, ip_a);
        assert_ne!(ip_c, ip_b);
        assert_eq!(new.lookup_domain(&ip_a), Some("a.com".to_string()));
    }

    #[test]
    fn clone_from_overwrites_target_state() {
        let old = make_pool();
        let ip_a = old.allocate("a.com");

        let new = make_pool();
        let ip_x = new.allocate("x.com"); // same slot as a.com in old
        new.clone_from(&old);

        // CloneTo semantics: target replaced wholesale
        assert_eq!(new.lookup_domain(&ip_x), Some("a.com".to_string()));
        assert_eq!(new.allocate("a.com"), ip_a);
        assert!(new.domain_to_ip.get("x.com").is_none());
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
