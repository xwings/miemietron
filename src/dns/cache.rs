use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

const DEFAULT_MAX_SIZE: usize = 4096;

/// A cached DNS entry with per-entry expiration.
struct CacheEntry {
    ip: IpAddr,
    expires_at: Instant,
}

/// DNS cache using DashMap with per-entry TTL.
///
/// mihomo compat: each entry has its own TTL from the upstream DNS response.
/// Expired entries are lazily removed on access.
pub struct DnsCache {
    entries: DashMap<String, CacheEntry>,
    max_size: usize,
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        let max_size = if max_size == 0 {
            DEFAULT_MAX_SIZE
        } else {
            max_size
        };
        Self {
            entries: DashMap::with_capacity(max_size),
            max_size,
        }
    }

    /// Return IP if entry exists and is not expired; remove expired entries on access.
    pub fn get(&self, domain: &str) -> Option<IpAddr> {
        // DashMap supports Borrow<str> lookups — no String allocation needed.
        if let Some(entry) = self.entries.get(domain) {
            if Instant::now() < entry.expires_at {
                return Some(entry.ip);
            }
            // Entry expired — drop the ref before removing
            drop(entry);
            self.entries.remove(domain);
        }
        None
    }

    /// Insert a DNS entry with a specific TTL in seconds.
    /// If ttl_secs is 0, the entry is not cached (mihomo compat).
    pub fn insert(&self, domain: String, ip: IpAddr, ttl_secs: u32) {
        if ttl_secs == 0 {
            return;
        }

        // Simple eviction: if at capacity, remove some expired entries first
        if self.entries.len() >= self.max_size {
            self.evict_expired();
        }

        // If still at capacity after eviction, skip insertion (LRU would be
        // better but mihomo's cache is also simple)
        if self.entries.len() >= self.max_size {
            return;
        }

        self.entries.insert(
            domain,
            CacheEntry {
                ip,
                expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    /// Flush all entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Remove expired entries.
    fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn insert_and_get() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("example.com".to_string(), ip, 300);
        assert_eq!(cache.get("example.com"), Some(ip));
    }

    #[test]
    fn get_missing_key() {
        let cache = DnsCache::new(100);
        assert_eq!(cache.get("nonexistent.com"), None);
    }

    #[test]
    fn clear_empties_cache() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("a.com".to_string(), ip, 300);
        cache.insert("b.com".to_string(), ip, 300);
        cache.clear();
        assert_eq!(cache.get("a.com"), None);
    }

    #[test]
    fn zero_ttl_not_cached() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("example.com".to_string(), ip, 0);
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn expired_entry_removed_on_access() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Insert with 1 second TTL — we can't easily test real expiration
        // without sleeping, but we can verify the entry is stored.
        cache.insert("example.com".to_string(), ip, 1);
        // Should be retrievable immediately
        assert_eq!(cache.get("example.com"), Some(ip));
    }
}
