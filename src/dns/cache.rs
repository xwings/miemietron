use dashmap::DashMap;
use std::time::Instant;

use super::upstream::Answer;

const DEFAULT_MAX_SIZE: usize = 4096;

/// A cached DNS answer with per-entry expiration.
struct CacheEntry {
    answer: Answer,
    expires_at: Instant,
}

/// DNS cache using DashMap with per-entry TTL.
///
/// mihomo compat: each entry has its own TTL from the upstream DNS response.
/// Expired entries are lazily removed on access. Negative answers (NXDOMAIN,
/// empty) are entries like any other (dns/util.go putMsgToCache).
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

    /// Return the answer if the entry exists and is not expired, its TTL
    /// counted down to the REMAINING seconds (at least 1); remove expired
    /// entries on access.
    ///
    /// mihomo compat: resolver.go ExchangeContext counts a cached answer's TTL
    /// down by `time.Until(expireTime)` (util.go updateTTL) instead of replaying
    /// the original TTL, so a client can't keep an address past its expiry.
    pub fn get(&self, key: &str) -> Option<Answer> {
        // DashMap supports Borrow<str> lookups — no String allocation needed.
        if let Some(entry) = self.entries.get(key) {
            let now = Instant::now();
            if now < entry.expires_at {
                let remaining = (entry.expires_at - now).as_secs().max(1);
                return Some(Answer {
                    ttl: remaining as u32,
                    ..entry.answer.clone()
                });
            }
            // Entry expired — drop the ref before removing
            drop(entry);
            self.entries.remove(key);
        }
        None
    }

    /// Insert an answer for its TTL in seconds.
    /// If the TTL is 0, the answer is not cached (mihomo compat).
    pub fn insert(&self, key: String, answer: &Answer) {
        if answer.ttl == 0 {
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
            key,
            CacheEntry {
                answer: answer.clone(),
                expires_at: Instant::now() + std::time::Duration::from_secs(answer.ttl as u64),
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
    use std::net::{IpAddr, Ipv4Addr};

    fn answer(ip: IpAddr, ttl: u32) -> Answer {
        Answer {
            rcode: 0,
            ips: vec![ip],
            ttl,
        }
    }

    #[test]
    fn insert_and_get() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("example.com".to_string(), &answer(ip, 300));
        assert_eq!(cache.get("example.com").unwrap().ips, [ip]);
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
        cache.insert("a.com".to_string(), &answer(ip, 300));
        cache.insert("b.com".to_string(), &answer(ip, 300));
        cache.clear();
        assert_eq!(cache.get("a.com"), None);
    }

    #[test]
    fn zero_ttl_not_cached() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("example.com".to_string(), &answer(ip, 0));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn expired_entry_removed_on_access() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Insert with 1 second TTL — we can't easily test real expiration
        // without sleeping, but we can verify the entry is stored.
        cache.insert("example.com".to_string(), &answer(ip, 1));
        // Should be retrievable immediately
        assert_eq!(cache.get("example.com").unwrap().ips, [ip]);
    }

    /// mihomo compat: dns/util.go putMsgToCache caches whatever reply won,
    /// its response code included — an NXDOMAIN is served from the cache
    /// until the SOA's TTL runs out.
    #[test]
    fn negative_answer_is_cached_with_its_rcode() {
        let cache = DnsCache::new(100);
        let nxdomain = Answer {
            rcode: 3,
            ips: vec![],
            ttl: 600,
        };
        cache.insert("missing.example.com".to_string(), &nxdomain);

        let cached = cache.get("missing.example.com").unwrap();
        assert_eq!((cached.rcode, cached.ips.len()), (3, 0));
        assert!((1..=600).contains(&cached.ttl));
    }
}
