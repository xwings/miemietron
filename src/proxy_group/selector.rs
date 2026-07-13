use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tokio::sync::Notify;

use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

use super::proxy_state::ProxyStateStore;
use super::{HealthCheckOpts, ProxyGroup};

/// Optional health-check state for a select group.
///
/// mihomo compat: parser.go:166-171 leaves `interval` at 0 for select groups
/// (only non-select types get the 300s default), and healthcheck.go auto()
/// runs the periodic check only when interval != 0 — so a select group is
/// health-checked only when the user configures an interval.
pub(crate) struct SelectorHealthCheck {
    pub(crate) test_url: String,
    pub(crate) interval: Duration,
    pub(crate) lazy: bool,
    pub(crate) test_timeout: u64,
    pub(crate) expected_status: Option<Vec<(u16, u16)>>,
    pub(crate) state_store: Arc<ProxyStateStore>,
    pub(crate) last_touch: Arc<AtomicU64>,
    pub(crate) health_notify: Arc<Notify>,
}

/// Manual proxy selection group.
///
/// The user picks which proxy to use via the API. The selection is persisted
/// in memory (a `parking_lot::RwLock<String>`) and survives concurrent reads
/// without contention.
pub struct SelectorGroup {
    group_name: String,
    proxy_names: Vec<String>,
    current: RwLock<String>,
    health: Option<SelectorHealthCheck>,
}

impl SelectorGroup {
    pub fn new(name: String, proxies: Vec<String>) -> Self {
        let initial = proxies.first().cloned().unwrap_or_default();
        Self {
            group_name: name,
            proxy_names: proxies,
            current: RwLock::new(initial),
            health: None,
        }
    }

    /// Construct a select group with a periodic health check (mihomo compat:
    /// user configured a non-zero `interval` — see SelectorHealthCheck docs).
    pub fn with_health_check(
        name: String,
        proxies: Vec<String>,
        hc: HealthCheckOpts,
        state_store: Arc<ProxyStateStore>,
    ) -> Self {
        let mut group = Self::new(name, proxies);
        group.health = Some(SelectorHealthCheck {
            test_url: hc.url,
            interval: Duration::from_secs(hc.interval_secs),
            lazy: hc.lazy,
            test_timeout: hc.test_timeout.unwrap_or(5000),
            expected_status: hc.expected_status,
            state_store,
            last_touch: Arc::new(AtomicU64::new(0)),
            health_notify: Arc::new(Notify::new()),
        });
        group
    }

    /// The health-check state, if this select group has one configured.
    pub(crate) fn health(&self) -> Option<&SelectorHealthCheck> {
        self.health.as_ref()
    }

    /// Run a health check against all proxies concurrently through their
    /// actual proxy connections. No-op when no health check is configured.
    pub async fn health_check(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        let Some(hc) = &self.health else { return };
        super::health::run_health_check(
            "select",
            &self.proxy_names,
            &hc.test_url,
            hc.test_timeout,
            hc.expected_status.clone(),
            proxies,
            dns,
            &hc.state_store,
        )
        .await;
    }
}

impl ProxyGroup for SelectorGroup {
    fn name(&self) -> &str {
        &self.group_name
    }

    fn group_type(&self) -> &str {
        "Selector"
    }

    fn now(&self) -> String {
        self.current.read().clone()
    }

    fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    fn select(&self, name: &str) -> bool {
        if self.proxy_names.iter().any(|n| n == name) {
            *self.current.write() = name.to_string();
            true
        } else {
            false
        }
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        let selected = self.current.read().clone();
        proxies.get(&selected).cloned()
    }

    /// mihomo compat: provider Touch() drives the lazy health check.
    fn touch(&self) {
        if let Some(hc) = &self.health {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            hc.last_touch.store(now, Ordering::Relaxed);
        }
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_first_proxy() {
        let group = SelectorGroup::new(
            "test-select".to_string(),
            vec![
                "proxy-a".to_string(),
                "proxy-b".to_string(),
                "proxy-c".to_string(),
            ],
        );
        assert_eq!(group.now(), "proxy-a");
    }

    #[test]
    fn select_changes_active_proxy() {
        let group = SelectorGroup::new(
            "test-select".to_string(),
            vec!["proxy-a".to_string(), "proxy-b".to_string()],
        );
        assert_eq!(group.now(), "proxy-a");

        assert!(group.select("proxy-b"));
        assert_eq!(group.now(), "proxy-b");
    }

    #[test]
    fn select_invalid_name_returns_false() {
        let group = SelectorGroup::new(
            "test-select".to_string(),
            vec!["proxy-a".to_string(), "proxy-b".to_string()],
        );
        assert!(!group.select("nonexistent"));
        // The selection should be unchanged.
        assert_eq!(group.now(), "proxy-a");
    }

    #[test]
    fn all_returns_all_proxies() {
        let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let group = SelectorGroup::new("test".to_string(), names.clone());
        assert_eq!(group.all(), names);
    }

    #[test]
    fn group_type_is_selector() {
        let group = SelectorGroup::new("g".to_string(), vec!["x".to_string()]);
        assert_eq!(group.group_type(), "Selector");
    }

    #[test]
    fn name_matches_construction() {
        let group = SelectorGroup::new("my-group".to_string(), vec![]);
        assert_eq!(group.name(), "my-group");
    }

    #[test]
    fn empty_proxies_now_returns_empty_string() {
        let group = SelectorGroup::new("empty".to_string(), vec![]);
        assert_eq!(group.now(), "");
    }
}
