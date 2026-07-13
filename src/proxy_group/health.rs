//! Background health-check loop for proxy groups.
//!
//! Spawns a tokio task per group that periodically tests all proxies by
//! connecting through each proxy and issuing HTTP HEAD requests to the
//! configured test URL. The results are used by `UrlTestGroup` (auto-select
//! fastest), `FallbackGroup` (first alive), `LoadBalanceGroup` (skip dead
//! nodes) and select groups with a configured interval.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time;
use tracing::{debug, info, warn};

use super::fallback::FallbackGroup;
use super::load_balance::LoadBalanceGroup;
use super::proxy_state::ProxyStateStore;
use super::selector::SelectorGroup;
use super::url_test::{measure_unified_delay, UrlTestGroup};
use super::{status_matches, ProxyGroup};
use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

/// Run one health-check pass: probe every proxy in `names` through its own
/// connection against `url`, recording results in `store`.
///
/// mihomo compat: healthcheck.go check()/execute() — errgroup.SetLimit(10)
/// bounds concurrency (spawning ALL proxies at once accumulates hundreds of
/// hanging TCP connections on ARM routers); each probe is proxy.URLTest()
/// with the per-check timeout. On an unexpected HTTP status (expected-status
/// mismatch) adapter.go URLTest() keeps the DEFAULT state alive with the
/// real delay and marks only the per-URL extra state dead.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_health_check(
    kind: &str,
    names: &[String],
    url: &str,
    timeout_ms: u64,
    expected_status: Option<Vec<(u16, u16)>>,
    proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    dns: &Arc<DnsResolver>,
    store: &Arc<ProxyStateStore>,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
    let expected = Arc::new(expected_status);
    let mut handles = Vec::new();
    let timeout = Duration::from_millis(timeout_ms);

    for name in names {
        let handler = match proxies.get(name) {
            Some(h) => h.clone(),
            None => continue,
        };
        let name = name.clone();
        let kind = kind.to_string();
        let url = url.to_string();
        let dns = dns.clone();
        let store = store.clone();
        let sem = semaphore.clone();
        let expected = expected.clone();

        handles.push(tokio::spawn(async move {
            // Acquire semaphore permit (max 10 concurrent checks)
            let _permit = sem.acquire().await;
            // mihomo compat: per-proxy timeout from hc.timeout (default 5000ms)
            let result =
                tokio::time::timeout(timeout, measure_unified_delay(&handler, &url, &dns)).await;
            match result {
                Ok(Ok((ms, status))) => {
                    let delay = if ms > u16::MAX as u64 {
                        u16::MAX
                    } else {
                        ms as u16
                    };
                    let satisfied = expected
                        .as_deref()
                        .is_none_or(|r| status_matches(status, r));
                    if satisfied {
                        debug!("{} {}: {}ms", kind, name, ms);
                        store.record_result(&name, &url, Some(delay));
                    } else {
                        // mihomo compat: adapter.go URLTest — unexpected status
                        // keeps the default state alive with the real delay;
                        // only the per-URL extra state goes dead.
                        warn!("{} {}: unexpected status {}", kind, name, status);
                        store.record_unexpected_status(&name, &url, delay);
                    }
                }
                Ok(Err(e)) => {
                    warn!("{} {}: {}", kind, name, e);
                    store.record_result(&name, &url, None);
                }
                Err(_) => {
                    warn!("{} {}: timeout", kind, name);
                    store.record_result(&name, &url, None);
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}

/// A type-erased handle to a group that supports health checking.
enum HealthCheckable {
    UrlTest(Arc<UrlTestGroup>),
    Fallback(Arc<FallbackGroup>),
    LoadBalance(Arc<LoadBalanceGroup>),
    Selector(Arc<SelectorGroup>),
}

impl HealthCheckable {
    fn interval(&self) -> Duration {
        match self {
            HealthCheckable::UrlTest(g) => g.interval(),
            HealthCheckable::Fallback(g) => g.interval(),
            HealthCheckable::LoadBalance(g) => g.interval(),
            HealthCheckable::Selector(g) => g.health().map(|h| h.interval).unwrap_or_default(),
        }
    }

    /// Whether this group uses lazy health checks.
    fn lazy(&self) -> bool {
        match self {
            HealthCheckable::UrlTest(g) => g.lazy,
            HealthCheckable::Fallback(g) => g.lazy,
            HealthCheckable::LoadBalance(g) => g.lazy,
            HealthCheckable::Selector(g) => g.health().map(|h| h.lazy).unwrap_or(true),
        }
    }

    /// Get the last touch timestamp (epoch millis) for lazy health check.
    fn last_touch_millis(&self) -> u64 {
        match self {
            HealthCheckable::UrlTest(g) => g.last_touch.load(Ordering::Relaxed),
            HealthCheckable::Fallback(g) => g.last_touch.load(Ordering::Relaxed),
            HealthCheckable::LoadBalance(g) => g.last_touch.load(Ordering::Relaxed),
            HealthCheckable::Selector(g) => g
                .health()
                .map(|h| h.last_touch.load(Ordering::Relaxed))
                .unwrap_or(0),
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
            HealthCheckable::LoadBalance(g) => g.health_check(proxies, dns).await,
            HealthCheckable::Selector(g) => g.health_check(proxies, dns).await,
        }
    }

    /// Called after a health check completes to reset cached state.
    /// For UrlTestGroup, resets the fast_single cache.
    fn after_health_check(&self) {
        if let HealthCheckable::UrlTest(g) = self {
            g.reset_fast_single()
        }
    }

    /// Notify handle used by `on_dial_failed` to trigger an immediate check.
    /// mihomo compat: matches GroupBase.healthCheck() being called from
    /// onDialFailed paths.
    fn health_notify(&self) -> Arc<Notify> {
        match self {
            HealthCheckable::UrlTest(g) => g.health_notify.clone(),
            HealthCheckable::Fallback(g) => g.health_notify.clone(),
            HealthCheckable::LoadBalance(g) => g.health_notify.clone(),
            // try_into_checkable only yields Selector when health() is Some.
            HealthCheckable::Selector(g) => g
                .health()
                .expect("Selector checkable always has health configured")
                .health_notify
                .clone(),
        }
    }

    /// Toggle the `failedTesting` flag while a triggered check runs.
    /// mihomo compat: groupbase.go healthCheck() sets/clears failedTesting.
    /// Selector has no onDial hooks in mihomo, so it is a no-op there.
    fn set_health_testing(&self, running: bool) {
        match self {
            HealthCheckable::UrlTest(g) => g.set_health_testing(running),
            HealthCheckable::Fallback(g) => g.set_health_testing(running),
            HealthCheckable::LoadBalance(g) => g.set_health_testing(running),
            HealthCheckable::Selector(_) => {}
        }
    }
}

/// Spawn background health-check tasks for all url-test, fallback and
/// load-balance groups, plus select groups with a configured interval.
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
        let Some(checkable) = try_into_checkable(group) else {
            continue;
        };
        let interval = checkable.interval();
        let group_name = name.clone();
        let proxies = proxies.clone();
        let dns = dns.clone();

        let lazy = checkable.lazy();
        let notify = checkable.health_notify();
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
            }
        });

        handles.push(handle);
    }

    handles
}

/// Try to downcast a `dyn ProxyGroup` to a type that supports health checking.
fn try_into_checkable(group: &Arc<dyn ProxyGroup>) -> Option<HealthCheckable> {
    let any = group.clone().as_any_arc();
    let any = match any.downcast::<UrlTestGroup>() {
        Ok(g) => return Some(HealthCheckable::UrlTest(g)),
        Err(any) => any,
    };
    let any = match any.downcast::<FallbackGroup>() {
        Ok(g) => return Some(HealthCheckable::Fallback(g)),
        Err(any) => any,
    };
    // mihomo compat: parser.go:166-171 — load-balance is a non-select
    // type, so it always gets a periodic health check (interval
    // defaults to 300s).
    let any = match any.downcast::<LoadBalanceGroup>() {
        Ok(g) => return Some(HealthCheckable::LoadBalance(g)),
        Err(any) => any,
    };
    // mihomo compat: healthcheck.go auto() — select groups run
    // periodic checks only when the user configured an interval.
    if let Ok(g) = any.downcast::<SelectorGroup>() {
        if g.health().is_some() {
            return Some(HealthCheckable::Selector(g));
        }
    }
    None
}
