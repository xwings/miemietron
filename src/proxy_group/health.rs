//! Background health-check loop for proxy groups.
//!
//! Spawns a tokio task per group that periodically tests all proxies by
//! connecting through each proxy and issuing HTTP HEAD requests to the
//! configured test URL. The results are used by `UrlTestGroup` (auto-select
//! fastest) and `FallbackGroup` (first alive).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

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
        let handle = tokio::spawn(async move {
            info!(
                "Health check loop started for '{}' (interval: {:?}, lazy: {})",
                group_name, interval, lazy
            );

            // Run an initial check immediately
            checkable.health_check(&proxies, &dns).await;
            checkable.after_health_check();

            let mut ticker = time::interval(interval);
            // The first tick fires immediately — we already did the initial
            // check above, so skip it.
            ticker.tick().await;

            loop {
                ticker.tick().await;

                // mihomo compat: lazy health check mode.
                // If lazy is enabled, skip the check if the group hasn't been
                // used (touched) within the last interval.
                // Matches mihomo's healthcheck.go process() logic.
                if lazy {
                    let last = checkable.last_touch_millis();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    if last == 0 || now.saturating_sub(last) > interval.as_millis() as u64 {
                        debug!(
                            "Skip health check for '{}' (lazy, idle)",
                            group_name
                        );
                        continue;
                    }
                }

                debug!("Running health check for '{}'", group_name);
                checkable.health_check(&proxies, &dns).await;
                checkable.after_health_check();
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
