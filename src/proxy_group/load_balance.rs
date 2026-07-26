use std::collections::{HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

use super::proxy_state::ProxyStateStore;
use super::{GroupBase, HealthCheckOpts, ProxyGroup};

/// Load-balancing strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    /// Hash the destination address to deterministically pick a proxy.
    ConsistentHashing,
    /// Simple round-robin counter.
    RoundRobin,
    /// Sticky sessions: remember which proxy was used for each destination
    /// (bounded LRU via an ordered map).
    StickySession,
}

impl LoadBalanceStrategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "round-robin" => Self::RoundRobin,
            "sticky-sessions" => Self::StickySession,
            // default / "consistent-hashing"
            _ => Self::ConsistentHashing,
        }
    }
}

/// Load-balance group: distributes traffic across proxies using one of
/// several strategies. All strategies skip dead nodes (mihomo compat:
/// loadbalance.go strategy functions check AliveForTestUrl).
pub struct LoadBalanceGroup {
    /// mihomo compat: the embedded GroupBase (groupbase.go).
    base: GroupBase,
    strategy: LoadBalanceStrategy,
    /// Round-robin index (only used by RoundRobin strategy).
    /// mihomo compat: loadbalance.go strategyRoundRobin advances the index
    /// by the number of entries scanned, so dead nodes are skipped.
    rr_idx: Mutex<usize>,
    /// Sticky-session cache: destination -> proxy name (LRU, bounded).
    sticky_map: RwLock<HashMap<String, String>>,
    sticky_order: RwLock<VecDeque<String>>,
}

const STICKY_CACHE_MAX: usize = 1024;

/// Number of attempts before giving up on finding an alive node via hashing.
/// mihomo compat: loadbalance.go `maxRetry = 5`.
const MAX_RETRY: usize = 5;

/// Google's Jump Hash algorithm — matches mihomo's jumpHash() exactly.
/// Deterministically maps a key to a bucket in [0, buckets).
fn jump_hash(mut key: u64, buckets: i32) -> i32 {
    let mut b: i64 = 0;
    let mut j: i64 = 0;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * ((1i64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    b as i32
}

/// Extract the hash key from a destination string.
/// Approximates mihomo's getKey (loadbalance.go), which uses the
/// publicsuffix list for eTLD+1 — here a small two-part-TLD heuristic
/// stands in. IP addresses are used raw, as in mihomo.
fn get_key(dst: &str) -> String {
    // Strip port if present
    let host = if let Some(bracket_end) = dst.find(']') {
        // IPv6 with brackets: [::1]:port
        &dst[..bracket_end + 1]
    } else if let Some(idx) = dst.rfind(':') {
        &dst[..idx]
    } else {
        dst
    };

    // If it's an IP, return as-is
    let host_clean = host.trim_start_matches('[').trim_end_matches(']');
    if host_clean.parse::<std::net::IpAddr>().is_ok() {
        return host_clean.to_string();
    }

    // Extract eTLD+1: simple heuristic — take last 2 labels,
    // or 3 if the second-to-last is a known 2-part TLD component.
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    // Known 2-part TLD second-level components
    const TWO_PART_TLDS: &[&str] = &[
        "co", "com", "net", "org", "edu", "gov", "ac", "or", "ne", "go", "gob",
    ];
    let second_last = labels[labels.len() - 2];
    if TWO_PART_TLDS.contains(&second_last) && labels.len() >= 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

/// Hash a key string to a u64 (stand-in for mihomo's utils.MapHash).
fn hash_key(key_str: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    key_str.hash(&mut hasher);
    hasher.finish()
}

impl LoadBalanceGroup {
    pub fn new(
        name: String,
        proxies: Vec<String>,
        strategy: LoadBalanceStrategy,
        hc: HealthCheckOpts,
        state_store: Arc<ProxyStateStore>,
    ) -> Self {
        Self {
            base: GroupBase::new(name, proxies, hc, state_store),
            strategy,
            rr_idx: Mutex::new(0),
            sticky_map: RwLock::new(HashMap::new()),
            sticky_order: RwLock::new(VecDeque::new()),
        }
    }

    pub(crate) fn base(&self) -> &GroupBase {
        &self.base
    }

    /// Run a health check against all proxies concurrently through their
    /// actual proxy connections, matching mihomo's behavior.
    pub async fn health_check(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        self.base
            .run_health_check("load-balance", proxies, dns)
            .await;
    }

    fn alive(&self, name: &str) -> bool {
        self.base.alive(name)
    }

    /// mihomo compat: loadbalance.go strategyConsistentHashing — try
    /// jumpHash up to 5 times (key+1 each miss) skipping dead nodes, then
    /// traverse the whole list for any alive node, then fall back to the
    /// first proxy.
    fn pick_consistent_hash(&self, dst: &str) -> Option<String> {
        let names = self.base.proxy_names();
        if names.is_empty() {
            return None;
        }
        let mut key = hash_key(&get_key(dst));
        let buckets = names.len() as i32;
        for _ in 0..MAX_RETRY {
            let idx = jump_hash(key, buckets) as usize;
            let name = &names[idx];
            if self.alive(name) {
                return Some(name.clone());
            }
            key = key.wrapping_add(1);
        }

        // when availability is poor, traverse the entire list to get the
        // available nodes (loadbalance.go:174-179)
        for name in names {
            if self.alive(name) {
                return Some(name.clone());
            }
        }

        names.first().cloned()
    }

    /// mihomo compat: loadbalance.go strategyRoundRobin — scan from the
    /// current index for the first alive node, advancing the index by the
    /// number of entries consumed; fall back to the first proxy when
    /// nothing is alive.
    fn pick_round_robin(&self) -> Option<String> {
        let names = self.base.proxy_names();
        let length = names.len();
        if length == 0 {
            return None;
        }
        let mut idx = self.rr_idx.lock();
        let mut i = 0;
        let mut found = None;
        while i < length {
            let id = (*idx + i) % length;
            let name = &names[id];
            i += 1;
            if self.alive(name) {
                found = Some(name.clone());
                break;
            }
        }
        *idx = (*idx + i) % length;
        found.or_else(|| names.first().cloned())
    }

    fn pick_sticky(&self, dst: &str) -> Option<String> {
        self.sticky_map.read().get(dst).cloned()
    }

    fn insert_sticky(&self, dst: &str, proxy: &str) {
        let mut map = self.sticky_map.write();
        let mut order = self.sticky_order.write();
        if map.contains_key(dst) {
            // Update existing entry, move to back of LRU order
            map.insert(dst.to_string(), proxy.to_string());
            order.retain(|d| d != dst);
            order.push_back(dst.to_string());
        } else {
            // Evict oldest if at capacity
            if map.len() >= STICKY_CACHE_MAX {
                if let Some(oldest) = order.pop_front() {
                    map.remove(&oldest);
                }
            }
            map.insert(dst.to_string(), proxy.to_string());
            order.push_back(dst.to_string());
        }
    }

    /// mihomo compat: loadbalance.go strategyStickySessions — a cached node
    /// is reused only while alive; otherwise re-roll with
    /// jumpHash(key + now-nanos) up to 5 times, caching the first alive
    /// pick, and give up to proxies[0].
    fn pick_sticky_session(
        &self,
        dst: &str,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<String> {
        let names = self.base.proxy_names();
        if names.is_empty() {
            return None;
        }
        if let Some(cached) = self.pick_sticky(dst) {
            if self.base.contains(&cached) && proxies.contains_key(&cached) && self.alive(&cached) {
                return Some(cached);
            }
        }

        let key = hash_key(&get_key(dst));
        let buckets = names.len() as i32;
        for _ in 0..MAX_RETRY {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let idx = jump_hash(key.wrapping_add(nanos), buckets) as usize;
            let name = &names[idx];
            if self.alive(name) {
                self.insert_sticky(dst, name);
                return Some(name.clone());
            }
        }

        // mihomo compat: loadbalance.go:213-214 — cache and return proxies[0]
        let first = names.first().cloned();
        if let Some(ref f) = first {
            self.insert_sticky(dst, f);
        }
        first
    }
}

impl ProxyGroup for LoadBalanceGroup {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn group_type(&self) -> &str {
        "LoadBalance"
    }

    fn now(&self) -> String {
        // mihomo compat: loadbalance.go Now() returns "" — the group has no
        // single active member.
        String::new()
    }

    fn all(&self) -> Vec<String> {
        self.base.all()
    }

    fn select(&self, _name: &str) -> bool {
        false
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        if self.base.proxy_names().is_empty() {
            return None;
        }

        // TODO(parity): mihomo hashes the connection destination (lb.Unified)
        // — destination plumbing not yet wired, so hash key is constant.
        let name = match self.strategy {
            LoadBalanceStrategy::ConsistentHashing => self.pick_consistent_hash(""),
            LoadBalanceStrategy::RoundRobin => self.pick_round_robin(),
            LoadBalanceStrategy::StickySession => self.pick_sticky_session("", proxies),
        };

        name.and_then(|n| proxies.get(&n).cloned())
    }

    /// mihomo compat: GroupBase.onDialFailed() in groupbase.go
    fn on_dial_failed(&self, proxy_type: &str, err: &str) {
        self.base
            .on_dial_failed(proxy_type, err, || self.base.do_health_check());
    }

    /// mihomo compat: GroupBase.onDialSuccess() in groupbase.go
    fn on_dial_success(&self) {
        self.base.on_dial_success();
    }

    /// mihomo compat: GroupBase.Touch() in groupbase.go
    fn touch(&self) {
        self.base.touch();
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<ProxyStateStore> {
        Arc::new(ProxyStateStore::new())
    }

    const TEST_URL: &str = "http://test.example/204";

    fn make_hc() -> HealthCheckOpts {
        HealthCheckOpts {
            url: TEST_URL.to_string(),
            interval_secs: 300,
            max_failed_times: None,
            test_timeout: None,
            lazy: false,
            expected_status: None,
        }
    }

    fn make_group(
        proxies: Vec<&str>,
        strategy: LoadBalanceStrategy,
        store: Arc<ProxyStateStore>,
    ) -> LoadBalanceGroup {
        LoadBalanceGroup::new(
            "lb".to_string(),
            proxies.into_iter().map(String::from).collect(),
            strategy,
            make_hc(),
            store,
        )
    }

    #[test]
    fn consistent_hash_deterministic() {
        let group = make_group(
            vec!["a", "b", "c", "d"],
            LoadBalanceStrategy::ConsistentHashing,
            make_store(),
        );

        // Same destination should always produce the same pick.
        let p1 = group.pick_consistent_hash("example.com:443");
        let p2 = group.pick_consistent_hash("example.com:443");
        let p3 = group.pick_consistent_hash("example.com:443");
        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn consistent_hash_different_destinations_may_differ() {
        let group = make_group(
            vec!["a", "b", "c", "d"],
            LoadBalanceStrategy::ConsistentHashing,
            make_store(),
        );

        // Different eTLD+1 domains should produce different picks.
        // (get_key extracts eTLD+1, so subdomains of the same domain hash identically.)
        let mut picks = std::collections::HashSet::new();
        for i in 0..100 {
            picks.insert(group.pick_consistent_hash(&format!("example-{i}.com:443")));
        }
        // With 4 proxies and 100 different eTLD+1 domains, we should hit more than 1 bucket.
        assert!(picks.len() > 1);
    }

    #[test]
    fn consistent_hash_skips_dead_nodes() {
        // mihomo compat: loadbalance.go strategyConsistentHashing skips
        // !AliveForTestUrl nodes.
        let store = make_store();
        store.record_result("a", TEST_URL, None);
        store.record_result("b", TEST_URL, Some(100));
        let group = make_group(
            vec!["a", "b"],
            LoadBalanceStrategy::ConsistentHashing,
            store,
        );

        for i in 0..50 {
            assert_eq!(
                group.pick_consistent_hash(&format!("example-{i}.com:443")),
                Some("b".to_string())
            );
        }
    }

    #[test]
    fn round_robin_cycles_through_proxies() {
        let group = make_group(
            vec!["a", "b", "c"],
            LoadBalanceStrategy::RoundRobin,
            make_store(),
        );

        assert_eq!(group.pick_round_robin(), Some("a".to_string()));
        assert_eq!(group.pick_round_robin(), Some("b".to_string()));
        assert_eq!(group.pick_round_robin(), Some("c".to_string()));
        assert_eq!(group.pick_round_robin(), Some("a".to_string())); // wraps around
    }

    #[test]
    fn round_robin_skips_dead_nodes() {
        // mihomo compat: loadbalance.go strategyRoundRobin skips
        // !AliveForTestUrl nodes and advances past them.
        let store = make_store();
        store.record_result("b", TEST_URL, None);
        let group = make_group(vec!["a", "b", "c"], LoadBalanceStrategy::RoundRobin, store);

        assert_eq!(group.pick_round_robin(), Some("a".to_string()));
        assert_eq!(group.pick_round_robin(), Some("c".to_string()));
        assert_eq!(group.pick_round_robin(), Some("a".to_string()));
        assert_eq!(group.pick_round_robin(), Some("c".to_string()));
    }

    #[test]
    fn round_robin_all_dead_returns_first() {
        // mihomo compat: strategyRoundRobin returns proxies[0] when nothing
        // is alive.
        let store = make_store();
        store.record_result("a", TEST_URL, None);
        store.record_result("b", TEST_URL, None);
        let group = make_group(vec!["a", "b"], LoadBalanceStrategy::RoundRobin, store);

        assert_eq!(group.pick_round_robin(), Some("a".to_string()));
        assert_eq!(group.pick_round_robin(), Some("a".to_string()));
    }

    #[test]
    fn sticky_session_rerolls_when_cached_dead() {
        // mihomo compat: loadbalance.go strategyStickySessions re-rolls when
        // the cached node is dead. With only "a" alive and "a" first in the
        // list, every re-roll outcome converges on "a".
        let store = make_store();
        store.record_result("a", TEST_URL, Some(100));
        store.record_result("b", TEST_URL, None);
        let group = make_group(vec!["a", "b"], LoadBalanceStrategy::StickySession, store);
        group.insert_sticky("dest1", "b");

        let proxies: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        // proxies map is only consulted for the cached-node existence check;
        // an absent cached node also forces a re-roll.
        assert_eq!(
            group.pick_sticky_session("dest1", &proxies),
            Some("a".to_string())
        );
        // The re-rolled pick is cached.
        assert_eq!(group.pick_sticky("dest1"), Some("a".to_string()));
    }

    #[test]
    fn strategy_from_str() {
        assert_eq!(
            LoadBalanceStrategy::from_str("consistent-hashing"),
            LoadBalanceStrategy::ConsistentHashing,
        );
        assert_eq!(
            LoadBalanceStrategy::from_str("round-robin"),
            LoadBalanceStrategy::RoundRobin,
        );
        assert_eq!(
            LoadBalanceStrategy::from_str("sticky-sessions"),
            LoadBalanceStrategy::StickySession,
        );
        // Unknown defaults to ConsistentHashing.
        assert_eq!(
            LoadBalanceStrategy::from_str("unknown"),
            LoadBalanceStrategy::ConsistentHashing,
        );
    }

    #[test]
    fn group_type_is_load_balance() {
        let group = make_group(vec!["x"], LoadBalanceStrategy::RoundRobin, make_store());
        assert_eq!(group.group_type(), "LoadBalance");
    }

    #[test]
    fn now_is_empty() {
        // mihomo compat: loadbalance.go Now() returns "".
        let group = make_group(vec!["a"], LoadBalanceStrategy::RoundRobin, make_store());
        assert_eq!(group.now(), "");
    }

    #[test]
    fn select_always_returns_false() {
        let group = make_group(vec!["a"], LoadBalanceStrategy::RoundRobin, make_store());
        assert!(!group.select("a"));
    }

    #[test]
    fn empty_proxies_consistent_hash_returns_none() {
        let group = make_group(vec![], LoadBalanceStrategy::ConsistentHashing, make_store());
        assert_eq!(group.pick_consistent_hash("anything"), None);
    }

    #[test]
    fn sticky_session_insert_and_retrieve() {
        let group = make_group(
            vec!["a", "b"],
            LoadBalanceStrategy::StickySession,
            make_store(),
        );

        group.insert_sticky("dest1", "a");
        group.insert_sticky("dest2", "b");

        assert_eq!(group.pick_sticky("dest1"), Some("a".to_string()));
        assert_eq!(group.pick_sticky("dest2"), Some("b".to_string()));
        assert_eq!(group.pick_sticky("dest3"), None);
    }
}
