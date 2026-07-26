use std::collections::HashMap;
use std::sync::Arc;

use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

use super::proxy_state::ProxyStateStore;
use super::{GroupBase, HealthCheckOpts, ProxyGroup};

/// Fallback group: pick the first proxy that is alive.
///
/// Like UrlTest, it periodically health-checks all proxies through the actual
/// proxy connections. Unlike UrlTest, it does **not** pick the lowest-latency
/// proxy. Instead it walks the proxy list in order and returns the first one
/// whose last health check succeeded.
pub struct FallbackGroup {
    /// mihomo compat: the embedded GroupBase (groupbase.go).
    base: GroupBase,
    /// mihomo compat: force-pinned selection via API (Set/ForceSet).
    force_selected: parking_lot::RwLock<Option<String>>,
}

impl FallbackGroup {
    pub fn new(
        name: String,
        proxies: Vec<String>,
        hc: HealthCheckOpts,
        state_store: Arc<ProxyStateStore>,
    ) -> Self {
        Self {
            base: GroupBase::new(name, proxies, hc, state_store),
            force_selected: parking_lot::RwLock::new(None),
        }
    }

    pub(crate) fn base(&self) -> &GroupBase {
        &self.base
    }

    #[cfg(test)]
    pub fn test_url(&self) -> &str {
        self.base.test_url()
    }

    /// Run a health check against all proxies concurrently through their
    /// actual proxy connections, matching mihomo's behavior.
    pub async fn health_check(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        self.base.run_health_check("fallback", proxies, dns).await;
    }

    /// mihomo compat: fallback.go findAliveProxy — walk the list in config
    /// order. A pinned proxy is honored only while alive; when its entry is
    /// found dead the pin is CLEARED and the remaining proxies are scanned
    /// for the first alive one. Falls back to the first proxy.
    fn find_alive_proxy(&self) -> Option<String> {
        // Read-lock the pin; upgrade to a write lock only when a dead pin
        // must be cleared, so the hot path stays contention-free.
        let mut selected = self.force_selected.read().clone();
        for name in self.base.proxy_names() {
            match selected.as_deref() {
                None => {
                    if self.base.alive(name) {
                        return Some(name.clone());
                    }
                }
                Some(sel) => {
                    if name == sel {
                        if self.base.alive(name) {
                            return Some(name.clone());
                        }
                        *self.force_selected.write() = None;
                        selected = None;
                    }
                }
            }
        }
        self.base.proxy_names().first().cloned()
    }
}

impl ProxyGroup for FallbackGroup {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn group_type(&self) -> &str {
        "Fallback"
    }

    fn now(&self) -> String {
        // mihomo compat: fallback.go Now() — same findAliveProxy as routing,
        // so a dead pin never lingers in `now`.
        self.find_alive_proxy().unwrap_or_default()
    }

    fn all(&self) -> Vec<String> {
        self.base.all()
    }

    fn select(&self, name: &str) -> bool {
        // mihomo compat: Fallback supports force-pinning via Set/ForceSet.
        if self.base.contains(name) {
            *self.force_selected.write() = Some(name.to_string());
            // TODO: mihomo fallback.go Set() (fallback.go:124-146) fires a
            // one-shot URLTest with a 5s timeout against just the newly
            // pinned proxy when it is not alive. select() has no access to
            // the proxies map / DNS resolver here, so we trigger the group's
            // health-check loop instead, which re-probes all members.
            if !self.base.alive(name) {
                self.base.health_notify().notify_one();
            }
            true
        } else {
            false
        }
    }

    fn clear_selection(&self) {
        // mihomo compat: ForceSet("") — clear forced selection.
        *self.force_selected.write() = None;
    }

    fn fixed(&self) -> String {
        // mihomo compat: fallback.go:90 — `fixed` is the pinned name.
        self.force_selected.read().clone().unwrap_or_default()
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        // mihomo compat: fallback.go findAliveProxy — shared with now().
        if let Some(name) = self.find_alive_proxy() {
            if let Some(handler) = proxies.get(&name) {
                return Some(handler.clone());
            }
        }

        // Fallback: first in list resolvable to a handler.
        for name in self.base.proxy_names() {
            if let Some(handler) = proxies.get(name) {
                return Some(handler.clone());
            }
        }
        None
    }

    /// mihomo compat: GroupBase.onDialFailed() in groupbase.go
    fn on_dial_failed(&self, proxy_type: &str, err: &str) {
        self.base
            .on_dial_failed(proxy_type, err, || self.base.do_health_check());
    }

    /// mihomo compat: GroupBase.onDialSuccess() in groupbase.go
    fn on_dial_success(&self) {
        self.base.on_dial_success();
    }

    /// mihomo compat: GroupBase.Touch() in groupbase.go
    fn touch(&self) {
        self.base.touch();
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn make_store() -> Arc<ProxyStateStore> {
        Arc::new(ProxyStateStore::new())
    }

    fn make_hc(url: &str, interval: u64) -> HealthCheckOpts {
        HealthCheckOpts {
            url: url.to_string(),
            interval_secs: interval,
            max_failed_times: None,
            test_timeout: None,
            lazy: false,
            expected_status: None,
        }
    }

    #[test]
    fn defaults_are_correct() {
        let group = FallbackGroup::new(
            "fb".to_string(),
            vec!["a".to_string(), "b".to_string()],
            make_hc("http://test.example/204", 600),
            make_store(),
        );
        assert_eq!(group.name(), "fb");
        assert_eq!(group.group_type(), "Fallback");
        assert_eq!(group.base().interval(), Duration::from_secs(600));
        assert_eq!(group.test_url(), "http://test.example/204");
        assert_eq!(group.all(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn now_before_health_check_returns_first_proxy() {
        let group = FallbackGroup::new(
            "fb".to_string(),
            vec!["primary".to_string(), "backup".to_string()],
            make_hc("http://test.example/204", 300),
            make_store(),
        );
        // No health check has run, alive map is empty.
        assert_eq!(group.now(), "primary");
    }

    #[test]
    fn select_force_pins_proxy() {
        let group = FallbackGroup::new(
            "fb".to_string(),
            vec!["a".to_string(), "b".to_string()],
            make_hc("http://test.example/204", 300),
            make_store(),
        );
        assert!(group.select("b"));
        assert_eq!(group.now(), "b");
        group.clear_selection();
        assert_eq!(group.now(), "a"); // falls back to first
        assert!(!group.select("nonexistent"));
    }

    #[test]
    fn empty_proxies_now_returns_empty_string() {
        let group = FallbackGroup::new(
            "empty".to_string(),
            vec![],
            make_hc("http://test.example/204", 300),
            make_store(),
        );
        assert_eq!(group.now(), "");
    }

    #[test]
    fn dead_pin_is_cleared_and_first_alive_wins() {
        // mihomo compat: fallback.go findAliveProxy — a dead pinned proxy
        // clears `selected`; now() and routing then agree on first-alive.
        let store = make_store();
        let url = "http://test.example/204";
        store.record_result("a", url, Some(100));
        store.record_result("b", url, None);

        let group = FallbackGroup::new(
            "fb".to_string(),
            vec!["a".to_string(), "b".to_string()],
            make_hc(url, 300),
            store.clone(),
        );
        assert!(group.select("b"));
        assert_eq!(group.fixed(), "b");

        // Pinned "b" is dead: falls back and the pin is cleared.
        assert_eq!(group.now(), "a");
        assert_eq!(group.fixed(), "");

        // "b" comes back alive: pin stays cleared, first alive still wins.
        store.record_result("b", url, Some(50));
        assert_eq!(group.now(), "a");
    }

    #[test]
    fn now_picks_first_alive() {
        let store = make_store();
        let url = "http://test.example/204";
        // Mark "primary" as dead, "backup" as alive
        store.record_result("primary", url, None);
        store.record_result("backup", url, Some(200));

        let group = FallbackGroup::new(
            "fb".to_string(),
            vec!["primary".to_string(), "backup".to_string()],
            make_hc(url, 300),
            store,
        );
        assert_eq!(group.now(), "backup");
    }
}
