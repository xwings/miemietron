use std::collections::HashMap;
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
    /// Sticky-session cache: destination -> proxy name.
    /// Bounded to 1024 entries; when full, the oldest entry is evicted.
    sticky_cache: RwLock<Vec<(String, String)>>,
    /// Destination hint set by the caller before calling `get_proxy`.
    destination_hint: RwLock<String>,
}

const STICKY_CACHE_MAX: usize = 1024;

impl LoadBalanceGroup {
    pub fn new(name: String, proxies: Vec<String>, strategy: LoadBalanceStrategy) -> Self {
        Self {
            group_name: name,
            proxy_names: proxies,
            strategy,
            rr_counter: AtomicUsize::new(0),
            sticky_cache: RwLock::new(Vec::new()),
            destination_hint: RwLock::new(String::new()),
        }
    }

    /// Set the destination hint used by consistent-hashing and sticky-session
    /// strategies. Must be called before `get_proxy`.
    pub fn set_destination_hint(&self, dst: &str) {
        *self.destination_hint.write() = dst.to_string();
    }

    fn pick_consistent_hash(&self, dst: &str) -> usize {
        if self.proxy_names.is_empty() {
            return 0;
        }
        let mut hasher = DefaultHasher::new();
        dst.hash(&mut hasher);
        (hasher.finish() as usize) % self.proxy_names.len()
    }

    fn pick_round_robin(&self) -> usize {
        if self.proxy_names.is_empty() {
            return 0;
        }
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        idx % self.proxy_names.len()
    }

    fn pick_sticky(&self, dst: &str) -> Option<String> {
        let cache = self.sticky_cache.read();
        for (d, proxy) in cache.iter().rev() {
            if d == dst {
                return Some(proxy.clone());
            }
        }
        None
    }

    fn insert_sticky(&self, dst: &str, proxy: &str) {
        let mut cache = self.sticky_cache.write();
        // Remove existing entry for this destination.
        cache.retain(|(d, _)| d != dst);
        // Evict oldest if at capacity.
        if cache.len() >= STICKY_CACHE_MAX {
            cache.remove(0);
        }
        cache.push((dst.to_string(), proxy.to_string()));
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
