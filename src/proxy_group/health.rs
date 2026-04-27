//! Background health-check loop for proxy groups.
//!
//! Spawns a tokio task per group that periodically tests all proxies by
//! connecting through each proxy and issuing HTTP HEAD requests to the
//! configured test URL. The results are used by `UrlTestGroup` (auto-select
//! fastest) and `FallbackGroup` (first alive).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time;
use tracing::{debug, info};

use super::fallback::FallbackGroup;
use super::url_test::UrlTestGroup;
use super::ProxyGroup;
use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

/// A type-erased handle to a group that supports health checking.
enum HealthCheckable {
    UrlTest(Arc<UrlTestGroup>),
    Fallback(Arc<FallbackGroup>),
}

impl HealthCheckable {
    #[allow(dead_code)]
    fn name(&self) -> &str {
        match self {
            HealthCheckable::UrlTest(g) => g.name(),
            HealthCheckable::Fallback(g) => g.name(),
        }
    }

    fn interval(&self) -> Duration {
        match self {
            HealthCheckable::UrlTest(g) => g.interval(),
            HealthCheckable::Fallback(g) => g.interval(),
        }
    }

    /// Whether this group uses lazy health checks.
    fn lazy(&self) -> bool {
        match self {
            HealthCheckable::UrlTest(g) => g.lazy,
            HealthCheckable::Fallback(g) => g.lazy,
        }
    }

    /// Get the last touch timestamp (epoch millis) for lazy health check.
    fn last_touch_millis(&self) -> u64 {
        match self {
            HealthCheckable::UrlTest(g) => g.last_touch.load(Ordering::Relaxed),
            HealthCheckable::Fallback(g) => g.last_touch.load(Ordering::Relaxed),
        }
    }

    async fn health_check(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        match self {
            HealthCheckable::UrlTest(g) => g.health_check(proxies, dns).await,
            HealthCheckable::Fallback(g) => g.health_check(proxies, dns).await,
        }
    }

    /// Called after a health check completes to reset cached state.
    /// For UrlTestGroup, resets the fast_single cache.
    fn after_health_check(&self) {
        match self {
            HealthCheckable::UrlTest(g) => g.reset_fast_single(),
            HealthCheckable::Fallback(_) => {}
        }
    }

    /// Notify handle used by `on_dial_failed` to trigger an immediate check.
    /// mihomo compat: matches GroupBase.healthCheck() being called from
    /// onDialFailed paths.
    fn health_notify(&self) -> Arc<Notify> {
        match self {
            HealthCheckable::UrlTest(g) => g.health_notify.clone(),
            HealthCheckable::Fallback(g) => g.health_notify.clone(),
        }
    }

    /// Toggle the `failedTesting` flag while a triggered check runs.
    /// mihomo compat: groupbase.go healthCheck() sets/clears failedTesting.
    fn set_health_testing(&self, running: bool) {
        match self {
            HealthCheckable::UrlTest(g) => g.set_health_testing(running),
            HealthCheckable::Fallback(g) => g.set_health_testing(running),
        }
    }
}

/// Spawn background health-check tasks for all url-test and fallback groups.
///
/// All health checks use through-proxy latency measurement: connecting through
/// each proxy via `connect_stream()` and sending an HTTP HEAD request. This
/// matches mihomo's behavior where URLTest() in adapter.go routes through the
/// proxy's DialContext.
///
/// Returns a `Vec<JoinHandle>` that can be aborted on shutdown.
pub fn spawn_health_checks(
    groups: &HashMap<String, Arc<dyn ProxyGroup>>,
    proxies: HashMap<String, Arc<dyn OutboundHandler>>,
    dns: Arc<DnsResolver>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    let proxies = Arc::new(proxies);

    for (name, group) in groups {
        let checkable = try_into_checkable(group);
        if checkable.is_none() {
            continue;
        }
        let checkable = checkable.unwrap();
        let interval = checkable.interval();
        let group_name = name.clone();
        let proxies = proxies.clone();
        let dns = dns.clone();

        let lazy = checkable.lazy();
        let notify = checkable.health_notify();
        // mihomo compat: singleDo guard prevents overlapping health checks.
        // If a check is still running when the next tick fires, skip it.
        let checking = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(async move {
            info!(
                "Health check loop started for '{}' (interval: {:?}, lazy: {})",
                group_name, interval, lazy
            );

            // Run an initial check immediately
            checkable.health_check(&proxies, &dns).await;
            checkable.after_health_check();

            let mut ticker = time::interval(interval);
            ticker.tick().await;

            loop {
                // Wake on either the periodic tick or a failure-driven trigger
                // (on_dial_failed -> do_health_check -> notify_one).
                let triggered = tokio::select! {
                    _ = ticker.tick() => false,
                    _ = notify.notified() => true,
                };

                // Lazy mode applies only to the periodic tick. A failure-driven
                // trigger always runs — mihomo's GroupBase.healthCheck() does not
                // consult the lazy/lastTouch state.
                if !triggered && lazy {
                    let last = checkable.last_touch_millis();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    if last == 0 || now.saturating_sub(last) > interval.as_millis() as u64 {
                        debug!("Skip health check for '{}' (lazy, idle)", group_name);
                        continue;
                    }
                }

                // mihomo compat: singleDo dedup — skip if previous check is still running.
                // Matches healthcheck.go line 128: `singleDo.Do(func() { ... })`.
                if checking.swap(true, Ordering::SeqCst) {
                    debug!(
                        "Skip health check for '{}' (previous still running)",
                        group_name
                    );
                    continue;
                }
                let checking_flag = checking.clone();

                debug!(
                    "Running health check for '{}' ({})",
                    group_name,
                    if triggered { "triggered" } else { "periodic" }
                );
                if triggered {
                    checkable.set_health_testing(true);
                }
                checkable.health_check(&proxies, &dns).await;
                checkable.after_health_check();
                if triggered {
                    checkable.set_health_testing(false);
                }
                checking_flag.store(false, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    handles
}

/// Try to downcast a `dyn ProxyGroup` to a type that supports health checking.
fn try_into_checkable(group: &Arc<dyn ProxyGroup>) -> Option<HealthCheckable> {
    // We use the group_type() string to decide. This avoids requiring
    // `Any` on the trait (which would complicate the trait object).
    match group.group_type() {
        "URLTest" => {
            // SAFETY: we know the concrete type behind the trait object
            // because group_type() == "URLTest" is only returned by
            // UrlTestGroup. We clone the Arc and transmute. A safer
            // approach would be to add an `as_any()` method to ProxyGroup.
            //
            // For now we rely on the fact that ProxyManager builds these
            // objects and the type tag is authoritative.
            // Increment refcount via from_raw + into_raw round-trip
            let cloned = group.clone();
            let raw = Arc::into_raw(cloned) as *const UrlTestGroup;
            let arc = unsafe { Arc::from_raw(raw) };
            Some(HealthCheckable::UrlTest(arc))
        }
        "Fallback" => {
            let cloned = group.clone();
            let raw = Arc::into_raw(cloned) as *const FallbackGroup;
            let arc = unsafe { Arc::from_raw(raw) };
            Some(HealthCheckable::Fallback(arc))
        }
        _ => None,
    }
}
