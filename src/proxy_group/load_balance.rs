use std::collections::{HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::proxy::OutboundHandler;

use super::ProxyGroup;

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
/// several strategies.
pub struct LoadBalanceGroup {
    group_name: String,
    proxy_names: Vec<String>,
    strategy: LoadBalanceStrategy,
    /// Round-robin counter (only used by RoundRobin strategy).
    rr_counter: AtomicUsize,
    /// Sticky-session cache: destination -> proxy name (LRU, bounded).
    sticky_map: RwLock<HashMap<String, String>>,
    sticky_order: RwLock<VecDeque<String>>,
    /// Destination hint set by the caller before calling `get_proxy`.
    destination_hint: RwLock<String>,
}

const STICKY_CACHE_MAX: usize = 1024;

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
/// mihomo compat: uses eTLD+1 for domains, raw IP for IP addresses.
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

impl LoadBalanceGroup {
    pub fn new(name: String, proxies: Vec<String>, strategy: LoadBalanceStrategy) -> Self {
        Self {
            group_name: name,
            proxy_names: proxies,
            strategy,
            rr_counter: AtomicUsize::new(0),
            sticky_map: RwLock::new(HashMap::new()),
            sticky_order: RwLock::new(VecDeque::new()),
            destination_hint: RwLock::new(String::new()),
        }
    }

    /// Set the destination hint used by consistent-hashing and sticky-session
    /// strategies. Must be called before `get_proxy`.
    #[allow(dead_code)]
    pub fn set_destination_hint(&self, dst: &str) {
        *self.destination_hint.write() = dst.to_string();
    }

    fn pick_consistent_hash(&self, dst: &str) -> usize {
        if self.proxy_names.is_empty() {
            return 0;
        }
        let key_str = get_key(dst);
        let mut hasher = DefaultHasher::new();
        key_str.hash(&mut hasher);
        let hash = hasher.finish();
        jump_hash(hash, self.proxy_names.len() as i32) as usize
    }

    fn pick_round_robin(&self) -> usize {
        if self.proxy_names.is_empty() {
            return 0;
        }
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        idx % self.proxy_names.len()
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
}

impl ProxyGroup for LoadBalanceGroup {
    fn name(&self) -> &str {
        &self.group_name
    }

    fn group_type(&self) -> &str {
        "LoadBalance"
    }

    fn now(&self) -> String {
        // For display purposes, show the first proxy.
        self.proxy_names.first().cloned().unwrap_or_default()
    }

    fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    fn select(&self, _name: &str) -> bool {
        false
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        if self.proxy_names.is_empty() {
            return None;
        }

        let dst = self.destination_hint.read().clone();

        let name = match self.strategy {
            LoadBalanceStrategy::ConsistentHashing => {
                let idx = self.pick_consistent_hash(&dst);
                self.proxy_names.get(idx).cloned()
            }
            LoadBalanceStrategy::RoundRobin => {
                let idx = self.pick_round_robin();
                self.proxy_names.get(idx).cloned()
            }
            LoadBalanceStrategy::StickySession => {
                if let Some(cached) = self.pick_sticky(&dst) {
                    if self.proxy_names.contains(&cached) && proxies.contains_key(&cached) {
                        Some(cached)
                    } else {
                        // Cached proxy is gone; fall back to consistent hash.
                        let idx = self.pick_consistent_hash(&dst);
                        let picked = self.proxy_names.get(idx).cloned();
                        if let Some(ref p) = picked {
                            self.insert_sticky(&dst, p);
                        }
                        picked
                    }
                } else {
                    let idx = self.pick_consistent_hash(&dst);
                    let picked = self.proxy_names.get(idx).cloned();
                    if let Some(ref p) = picked {
                        self.insert_sticky(&dst, p);
                    }
                    picked
                }
            }
        };

        name.and_then(|n| proxies.get(&n).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_hash_deterministic() {
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            LoadBalanceStrategy::ConsistentHashing,
        );

        // Same destination should always produce the same index.
        let idx1 = group.pick_consistent_hash("example.com:443");
        let idx2 = group.pick_consistent_hash("example.com:443");
        let idx3 = group.pick_consistent_hash("example.com:443");
        assert_eq!(idx1, idx2);
        assert_eq!(idx2, idx3);
    }

    #[test]
    fn consistent_hash_different_destinations_may_differ() {
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            LoadBalanceStrategy::ConsistentHashing,
        );

        // Different eTLD+1 domains should produce different bucket indices.
        // (get_key extracts eTLD+1, so subdomains of the same domain hash identically.)
        let mut indices = std::collections::HashSet::new();
        for i in 0..100 {
            indices.insert(group.pick_consistent_hash(&format!("example-{}.com:443", i)));
        }
        // With 4 proxies and 100 different eTLD+1 domains, we should hit more than 1 bucket.
        assert!(indices.len() > 1);
    }

    #[test]
    fn round_robin_cycles_through_proxies() {
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            LoadBalanceStrategy::RoundRobin,
        );

        let idx0 = group.pick_round_robin();
        let idx1 = group.pick_round_robin();
        let idx2 = group.pick_round_robin();
        let idx3 = group.pick_round_robin();

        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert_eq!(idx3, 0); // wraps around
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
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec!["x".to_string()],
            LoadBalanceStrategy::RoundRobin,
        );
        assert_eq!(group.group_type(), "LoadBalance");
    }

    #[test]
    fn select_always_returns_false() {
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec!["a".to_string()],
            LoadBalanceStrategy::RoundRobin,
        );
        assert!(!group.select("a"));
    }

    #[test]
    fn empty_proxies_consistent_hash_returns_zero() {
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec![],
            LoadBalanceStrategy::ConsistentHashing,
        );
        assert_eq!(group.pick_consistent_hash("anything"), 0);
    }

    #[test]
    fn sticky_session_insert_and_retrieve() {
        let group = LoadBalanceGroup::new(
            "lb".to_string(),
            vec!["a".to_string(), "b".to_string()],
            LoadBalanceStrategy::StickySession,
        );

        group.insert_sticky("dest1", "a");
        group.insert_sticky("dest2", "b");

        assert_eq!(group.pick_sticky("dest1"), Some("a".to_string()));
        assert_eq!(group.pick_sticky("dest2"), Some("b".to_string()));
        assert_eq!(group.pick_sticky("dest3"), None);
    }
}
