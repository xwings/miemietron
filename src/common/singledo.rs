//! SingleDo deduplicates concurrent calls to an async function.
//!
//! Port of mihomo's `common/singledo/singledo.go`.
//! If a cached result exists within the `wait` duration, returns it.
//! If another call is in flight, waits for it instead of executing again.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;

#[allow(dead_code)]
struct Call<T: Clone + Send> {
    notify: Arc<Notify>,
    result: Mutex<Option<(T, Option<String>)>>,
}

#[allow(dead_code)]
struct CachedResult<T> {
    val: T,
    err: Option<String>,
    time: Instant,
}

pub struct SingleDo<T: Clone + Send> {
    #[allow(dead_code)]
    wait: Duration,
    inner: Mutex<SingleDoInner<T>>,
}

struct SingleDoInner<T: Clone + Send> {
    call: Option<Arc<Call<T>>>,
    result: Option<CachedResult<T>>,
}

impl<T: Clone + Send> SingleDo<T> {
    pub fn new(wait: Duration) -> Self {
        Self {
            wait,
            inner: Mutex::new(SingleDoInner {
                call: None,
                result: None,
            }),
        }
    }

    /// Execute `f` with deduplication.
    ///
    /// Returns `(value, error, shared)` where `shared` is true if the result
    /// was reused from cache or from another in-flight call.
    ///
    /// Matches mihomo's `Single.Do()` signature.
    #[allow(dead_code)]
    pub async fn do_once<F, Fut>(&self, f: F) -> (T, Option<String>, bool)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = (T, Option<String>)>,
    {
        // Lock, check cache and inflight, then unlock — mirrors mihomo's pattern
        let maybe_call = {
            let mut inner = self.inner.lock();

            // Check cached result
            if let Some(ref result) = inner.result {
                if result.time.elapsed() < self.wait {
                    return (result.val.clone(), result.err.clone(), true);
                }
            }
            // The result has expired, clear it
            // mihomo compat: matches exact clearing behavior
            inner.result = None;

            // Check if another call is in flight
            inner.call.as_ref().map(|call_m| call_m.clone())
        };

        // If there's an in-flight call, wait for it (outside the lock)
        // mihomo compat: mirrors `callM.wg.Wait()` pattern
        if let Some(call_m) = maybe_call {
            // Check if result is already available (call finished between our lock release
            // and reaching here). If not, wait for notification.
            loop {
                {
                    let result = call_m.result.lock();
                    if let Some(ref r) = *result {
                        return (r.0.clone(), r.1.clone(), true);
                    }
                }
                call_m.notify.notified().await;
            }
        }

        // No cached result and no in-flight call — we are the caller
        let call_m = Arc::new(Call {
            notify: Arc::new(Notify::new()),
            result: Mutex::new(None),
        });

        {
            let mut inner = self.inner.lock();
            inner.call = Some(call_m.clone());
        }

        // Execute the function outside the lock — mirrors mihomo's pattern
        let (val, err) = f().await;

        // Store result in the call so waiters can read it
        {
            let mut result = call_m.result.lock();
            *result = Some((val.clone(), err.clone()));
        }
        // Wake all waiters — mirrors mihomo's `callM.wg.Done()`
        call_m.notify.notify_waiters();

        // Cache the result and clear the in-flight call
        {
            let mut inner = self.inner.lock();
            // mihomo compat: only clear if it's still our call (maybe reset while fn was running)
            if let Some(ref current_call) = inner.call {
                if Arc::ptr_eq(current_call, &call_m) {
                    inner.call = None;
                    inner.result = Some(CachedResult {
                        val: val.clone(),
                        err: err.clone(),
                        time: Instant::now(),
                    });
                }
            }
        }

        (val, err, false)
    }

    /// Synchronous variant of `do_once` for cheap, non-async compute functions.
    ///
    /// Holds the inner mutex across `f()`, so callers must not perform blocking
    /// or async work inside `f`. Returns `(value, shared)` where `shared` is
    /// true if the value came from cache.
    ///
    /// mihomo compat: matches `Single.Do` behavior when wrapping a sync compute
    /// (urltest.go fast()), where Go's sync.Mutex serializes concurrent callers.
    pub fn do_sync<F: FnOnce() -> T>(&self, f: F) -> (T, bool) {
        let mut inner = self.inner.lock();
        if let Some(ref result) = inner.result {
            if result.time.elapsed() < self.wait {
                return (result.val.clone(), true);
            }
        }
        inner.result = None;
        let val = f();
        inner.result = Some(CachedResult {
            val: val.clone(),
            err: None,
            time: Instant::now(),
        });
        (val, false)
    }

    /// Clear cached result and in-flight call, forcing next call to execute.
    /// Matches mihomo's `Single.Reset()`.
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.call = None;
        inner.result = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_basic_dedup() {
        let single = Arc::new(SingleDo::new(Duration::from_millis(200)));
        let foo = Arc::new(AtomicI32::new(0));
        let shared_count = Arc::new(AtomicI32::new(0));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let single = single.clone();
            let foo = foo.clone();
            let shared_count = shared_count.clone();
            handles.push(tokio::spawn(async move {
                let (_, _, shared) = single
                    .do_once(|| {
                        let foo = foo.clone();
                        async move {
                            foo.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            (0, None)
                        }
                    })
                    .await;
                if shared {
                    shared_count.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(foo.load(Ordering::SeqCst), 1);
        assert_eq!(shared_count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_timer_cached() {
        let single = SingleDo::new(Duration::from_millis(200));
        let foo = Arc::new(AtomicI32::new(0));

        let foo_clone = foo.clone();
        single
            .do_once(|| {
                let foo = foo_clone;
                async move {
                    foo.fetch_add(1, Ordering::SeqCst);
                    (0, None)
                }
            })
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let foo_clone = foo.clone();
        let (_, _, shared) = single
            .do_once(|| {
                let foo = foo_clone;
                async move {
                    foo.fetch_add(1, Ordering::SeqCst);
                    (0, None)
                }
            })
            .await;

        assert_eq!(foo.load(Ordering::SeqCst), 1);
        assert!(shared);
    }

    #[tokio::test]
    async fn test_reset() {
        let single = SingleDo::new(Duration::from_millis(200));
        let foo = Arc::new(AtomicI32::new(0));

        let foo_clone = foo.clone();
        single
            .do_once(|| {
                let foo = foo_clone;
                async move {
                    foo.fetch_add(1, Ordering::SeqCst);
                    (0, None)
                }
            })
            .await;

        single.reset();

        let foo_clone = foo.clone();
        single
            .do_once(|| {
                let foo = foo_clone;
                async move {
                    foo.fetch_add(1, Ordering::SeqCst);
                    (0, None)
                }
            })
            .await;

        assert_eq!(foo.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_stale_result_re_executes() {
        let single = SingleDo::new(Duration::from_millis(50));
        let foo = Arc::new(AtomicI32::new(0));

        let foo_clone = foo.clone();
        single
            .do_once(|| {
                let foo = foo_clone;
                async move {
                    foo.fetch_add(1, Ordering::SeqCst);
                    (0, None)
                }
            })
            .await;

        // Wait for the cache to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        let foo_clone = foo.clone();
        let (_, _, shared) = single
            .do_once(|| {
                let foo = foo_clone;
                async move {
                    foo.fetch_add(1, Ordering::SeqCst);
                    (0, None)
                }
            })
            .await;

        assert_eq!(foo.load(Ordering::SeqCst), 2);
        assert!(!shared);
    }
}
