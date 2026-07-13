//! SingleDo deduplicates repeated calls to a compute function.
//!
//! Port of mihomo's `common/singledo/singledo.go`, reduced to the synchronous
//! path this codebase uses (urltest.go fast() via `do_sync`): a cached result
//! within the `wait` window is returned instead of re-executing, and `reset()`
//! forces the next call to execute.

use std::time::{Duration, Instant};

use parking_lot::Mutex;

struct CachedResult<T> {
    val: T,
    time: Instant,
}

pub struct SingleDo<T: Clone + Send> {
    wait: Duration,
    result: Mutex<Option<CachedResult<T>>>,
}

impl<T: Clone + Send> SingleDo<T> {
    pub fn new(wait: Duration) -> Self {
        Self {
            wait,
            result: Mutex::new(None),
        }
    }

    /// Execute `f` with deduplication.
    ///
    /// Holds the inner mutex across `f()`, so callers must not perform blocking
    /// or async work inside `f`. Returns `(value, shared)` where `shared` is
    /// true if the value came from cache.
    ///
    /// mihomo compat: matches `Single.Do` behavior when wrapping a sync compute
    /// (urltest.go fast()), where Go's sync.Mutex serializes concurrent callers.
    pub fn do_sync<F: FnOnce() -> T>(&self, f: F) -> (T, bool) {
        let mut result = self.result.lock();
        if let Some(ref cached) = *result {
            if cached.time.elapsed() < self.wait {
                return (cached.val.clone(), true);
            }
        }
        let val = f();
        *result = Some(CachedResult {
            val: val.clone(),
            time: Instant::now(),
        });
        (val, false)
    }

    /// Clear the cached result, forcing the next call to execute.
    /// Matches mihomo's `Single.Reset()`.
    pub fn reset(&self) {
        *self.result.lock() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_within_window_is_shared() {
        let single = SingleDo::new(Duration::from_millis(200));

        let (val, shared) = single.do_sync(|| 1);
        assert_eq!(val, 1);
        assert!(!shared);

        // Second call within the window returns the cached value.
        let (val, shared) = single.do_sync(|| 2);
        assert_eq!(val, 1);
        assert!(shared);
    }

    #[test]
    fn test_reset() {
        let single = SingleDo::new(Duration::from_millis(200));

        let (val, _) = single.do_sync(|| 1);
        assert_eq!(val, 1);

        single.reset();

        let (val, shared) = single.do_sync(|| 2);
        assert_eq!(val, 2);
        assert!(!shared);
    }

    #[test]
    fn test_stale_result_re_executes() {
        let single = SingleDo::new(Duration::from_millis(50));

        let (val, _) = single.do_sync(|| 1);
        assert_eq!(val, 1);

        // Wait for the cache to expire
        std::thread::sleep(Duration::from_millis(100));

        let (val, shared) = single.do_sync(|| 2);
        assert_eq!(val, 2);
        assert!(!shared);
    }
}
