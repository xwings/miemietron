use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(3600);
const DEFAULT_MAX_SIZE: usize = 4096;

struct CacheEntry {
    ip: IpAddr,
    expires_at: Instant,
}

pub struct DnsCache {
    entries: DashMap<String, CacheEntry>,
    max_size: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        let max_size = if max_size == 0 {
            DEFAULT_MAX_SIZE
        } else {
            max_size
        };
        Self {
            entries: DashMap::new(),
            max_size,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn get(&self, domain: &str) -> Option<IpAddr> {
        if let Some(entry) = self.entries.get(domain) {
            if entry.expires_at > Instant::now() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.ip);
            }
            // Expired - remove
            drop(entry);
            self.entries.remove(domain);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&self, domain: String, ip: IpAddr) {
        self.insert_with_ttl(domain, ip, DEFAULT_TTL);
    }

    pub fn insert_with_ttl(&self, domain: String, ip: IpAddr, ttl: Duration) {
        // Simple eviction: if over max_size, remove ~25% of entries
        if self.entries.len() >= self.max_size {
            let now = Instant::now();
            self.entries.retain(|_, v| v.expires_at > now);

            // If still over, just remove oldest
            if self.entries.len() >= self.max_size {
                let to_remove = self.max_size / 4;
                let keys: Vec<String> = self
                    .entries
                    .iter()
                    .take(to_remove)
                    .map(|e| e.key().clone())
                    .collect();
                for key in keys {
                    self.entries.remove(&key);
                }
            }
        }

        self.entries.insert(
            domain,
            CacheEntry {
                ip,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
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
        cache.insert("example.com".to_string(), ip);
        assert_eq!(cache.get("example.com"), Some(ip));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn get_missing_key() {
        let cache = DnsCache::new(100);
        assert_eq!(cache.get("nonexistent.com"), None);
    }

    #[test]
    fn ttl_expiry() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Use a TTL of 0 (effectively already expired after the next Instant::now() check)
        cache.insert_with_ttl("example.com".to_string(), ip, Duration::from_millis(0));
        // A small spin to guarantee the instant has passed
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn cache_eviction_when_full() {
        let cache = DnsCache::new(4);
        for i in 0..4 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8));
            cache.insert(format!("host{}.com", i), ip);
        }
        assert_eq!(cache.len(), 4);

        // Insert one more to trigger eviction
        let ip5 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        cache.insert("host5.com".to_string(), ip5);
        // After eviction, size should be less than max_size
        assert!(cache.len() <= 4);
        // The newly inserted entry should be present
        assert_eq!(cache.get("host5.com"), Some(ip5));
    }

    #[test]
    fn clear_empties_cache() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("a.com".to_string(), ip);
        cache.insert("b.com".to_string(), ip);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get("a.com"), None);
    }

    #[test]
    fn stats_tracking() {
        let cache = DnsCache::new(100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert("a.com".to_string(), ip);
        cache.get("a.com"); // hit
        cache.get("b.com"); // miss
        cache.get("a.com"); // hit
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
    }
}
