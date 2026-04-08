//! Per-proxy delay history tracking.
//!
//! Port of mihomo's delay history from `adapter/adapter.go` and
//! the queue from `common/queue/queue.go`.

use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;

/// mihomo compat: `defaultHistoriesNum = 10` in adapter.go
const MAX_HISTORY: usize = 10;

/// A single delay measurement.
/// Matches mihomo's `constant.DelayHistory`.
#[derive(Clone, Debug, Serialize)]
pub struct DelayHistory {
    pub time: DateTime<Utc>,
    pub delay: u16, // 0 = failed/timeout
}

/// Thread-safe bounded queue for delay measurements.
///
/// Port of mihomo's `common/queue/queue.go` specialized for DelayHistory.
/// mihomo uses Put + manual Len/Pop to enforce the bound; we replicate that
/// exact pattern here.
pub struct DelayQueue {
    inner: RwLock<Vec<DelayHistory>>,
}

impl DelayQueue {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Vec::with_capacity(MAX_HISTORY)),
        }
    }

    /// Append an entry. If the queue exceeds MAX_HISTORY, remove the oldest.
    ///
    /// mihomo compat: adapter.go calls `history.Put(record)` then checks
    /// `if history.Len() > defaultHistoriesNum { history.Pop() }`.
    /// We replicate that exact behavior.
    pub fn put(&self, entry: DelayHistory) {
        let mut items = self.inner.write();
        items.push(entry);
        if items.len() > MAX_HISTORY {
            items.remove(0);
        }
    }

    /// Remove and return the oldest entry.
    /// Matches mihomo's `Queue.Pop()`.
    #[allow(dead_code)]
    pub fn pop(&self) -> Option<DelayHistory> {
        let mut items = self.inner.write();
        if items.is_empty() {
            None
        } else {
            Some(items.remove(0))
        }
    }

    /// Return the most recent entry (last in queue).
    /// Matches mihomo's `Queue.Last()`.
    pub fn last(&self) -> Option<DelayHistory> {
        let items = self.inner.read();
        items.last().cloned()
    }

    /// Return a copy of all entries.
    /// Matches mihomo's `Queue.Copy()`.
    pub fn copy(&self) -> Vec<DelayHistory> {
        let items = self.inner.read();
        items.clone()
    }

    /// Return the number of entries.
    /// Matches mihomo's `Queue.Len()`.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        let items = self.inner.read();
        items.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DelayQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-proxy state for a specific test URL.
/// Matches mihomo's per-URL proxy state in `adapter.go`.
pub struct ProxyState {
    pub alive: AtomicBool,
    pub history: DelayQueue,
}

impl ProxyState {
    pub fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
            history: DelayQueue::new(),
        }
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Relaxed);
    }
}

impl Default for ProxyState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_entry(delay: u16) -> DelayHistory {
        DelayHistory {
            time: Utc::now(),
            delay,
        }
    }

    #[test]
    fn test_delay_queue_put_and_last() {
        let q = DelayQueue::new();
        assert!(q.last().is_none());
        assert!(q.is_empty());

        q.put(make_entry(100));
        assert_eq!(q.len(), 1);
        assert_eq!(q.last().unwrap().delay, 100);

        q.put(make_entry(200));
        assert_eq!(q.len(), 2);
        assert_eq!(q.last().unwrap().delay, 200);
    }

    #[test]
    fn test_delay_queue_pop() {
        let q = DelayQueue::new();
        assert!(q.pop().is_none());

        q.put(make_entry(10));
        q.put(make_entry(20));
        q.put(make_entry(30));

        let popped = q.pop().unwrap();
        assert_eq!(popped.delay, 10);
        assert_eq!(q.len(), 2);

        let popped = q.pop().unwrap();
        assert_eq!(popped.delay, 20);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_delay_queue_copy() {
        let q = DelayQueue::new();
        q.put(make_entry(10));
        q.put(make_entry(20));
        q.put(make_entry(30));

        let copy = q.copy();
        assert_eq!(copy.len(), 3);
        assert_eq!(copy[0].delay, 10);
        assert_eq!(copy[1].delay, 20);
        assert_eq!(copy[2].delay, 30);

        // Original unaffected
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_delay_queue_bounded_at_max_history() {
        let q = DelayQueue::new();

        // Fill to MAX_HISTORY
        for i in 0..MAX_HISTORY {
            q.put(make_entry(i as u16));
        }
        assert_eq!(q.len(), MAX_HISTORY);

        // Adding one more should evict the oldest (delay=0)
        q.put(make_entry(100));
        assert_eq!(q.len(), MAX_HISTORY);

        let items = q.copy();
        // Oldest should now be delay=1 (delay=0 was evicted)
        assert_eq!(items[0].delay, 1);
        // Newest should be delay=100
        assert_eq!(items[items.len() - 1].delay, 100);
    }

    #[test]
    fn test_delay_queue_bounded_overflow() {
        let q = DelayQueue::new();

        // Add 15 entries
        for i in 0..15u16 {
            q.put(make_entry(i));
        }

        assert_eq!(q.len(), MAX_HISTORY);

        let items = q.copy();
        // Oldest 5 should have been evicted, remaining should be 5..15
        for (idx, item) in items.iter().enumerate() {
            assert_eq!(item.delay, (idx + 5) as u16);
        }
    }

    #[test]
    fn test_proxy_state_alive() {
        let state = ProxyState::new();
        assert!(state.is_alive());

        state.set_alive(false);
        assert!(!state.is_alive());

        state.set_alive(true);
        assert!(state.is_alive());
    }

    #[test]
    fn test_proxy_state_with_history() {
        let state = ProxyState::new();
        assert!(state.is_alive());
        assert!(state.history.is_empty());

        state.history.put(make_entry(150));
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.history.last().unwrap().delay, 150);

        // Simulate a failed health check
        state.set_alive(false);
        state.history.put(make_entry(0));
        assert!(!state.is_alive());
        assert_eq!(state.history.last().unwrap().delay, 0);
    }
}
