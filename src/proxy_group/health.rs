//! Background health-check loop for proxy groups.
//!
//! Spawns a tokio task per group that periodically tests all proxies by
//! issuing HTTP HEAD requests to the configured test URL. The results are
//! used by `UrlTestGroup` (auto-select fastest) and `FallbackGroup` (first
//! alive).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time;
use tracing::{debug, info};

use super::fallback::FallbackGroup;
use super::url_test::UrlTestGroup;
use super::ProxyGroup;
use crate::proxy::OutboundHandler;

/// A type-erased handle to a group that supports health checking.
enum HealthCheckable {
    UrlTest(Arc<UrlTestGroup>),
    Fallback(Arc<FallbackGroup>),
}

impl HealthCheckable {
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

    async fn health_check(&self, proxies: &HashMap<String, Arc<dyn OutboundHandler>>) {
        match self {
            HealthCheckable::UrlTest(g) => g.health_check(proxies).await,
            HealthCheckable::Fallback(g) => g.health_check(proxies).await,
        }
    }
}

/// Spawn background health-check tasks for all url-test and fallback groups.
///
/// Returns a `Vec<JoinHandle>` that can be aborted on shutdown.
pub fn spawn_health_checks(
    groups: &HashMap<String, Arc<dyn ProxyGroup>>,
    proxies: HashMap<String, Arc<dyn OutboundHandler>>,
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

        let handle = tokio::spawn(async move {
            info!(
                "Health check loop started for '{}' (interval: {:?})",
                group_name, interval
            );

            // Run an initial check immediately
            checkable.health_check(&proxies).await;

            let mut ticker = time::interval(interval);
            // The first tick fires immediately — we already did the initial
            // check above, so skip it.
            ticker.tick().await;

            loop {
                ticker.tick().await;
                debug!("Running health check for '{}'", group_name);
                checkable.health_check(&proxies).await;
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
