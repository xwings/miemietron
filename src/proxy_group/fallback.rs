use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

use super::proxy_state::ProxyStateStore;
use super::{HealthCheckOpts, ProxyGroup};

/// Fallback group: pick the first proxy that is alive.
///
/// Like UrlTest, it periodically health-checks all proxies through the actual
/// proxy connections. Unlike UrlTest, it does **not** pick the lowest-latency
/// proxy. Instead it walks the proxy list in order and returns the first one
/// whose last health check succeeded.
pub struct FallbackGroup {
    group_name: String,
    proxy_names: Vec<String>,
    test_url: String,
    interval: Duration,
    /// mihomo compat: expected-status ranges for the health check.
    expected_status: Option<Vec<(u16, u16)>>,
    /// Centralized state store for delay/alive tracking.
    state_store: Arc<ProxyStateStore>,
    /// mihomo compat: force-pinned selection via API (Set/ForceSet).
    force_selected: parking_lot::RwLock<Option<String>>,
    /// mihomo compat: onDialFailed tracking fields (from GroupBase).
    failed_times: AtomicU32,
    failed_time: parking_lot::Mutex<Instant>,
    failed_testing: AtomicBool,
    max_failed_times: u32,
    test_timeout: u64,
    /// mihomo compat: lazy health check — tracks when group was last used.
    /// Epoch millis.
    pub(crate) last_touch: Arc<AtomicU64>,
    /// Whether this group uses lazy health checks.
    pub(crate) lazy: bool,
    /// mihomo compat: failure-driven health check trigger.
    pub(crate) health_notify: Arc<Notify>,
}

impl FallbackGroup {
    pub fn new(
        name: String,
        proxies: Vec<String>,
        hc: HealthCheckOpts,
        state_store: Arc<ProxyStateStore>,
    ) -> Self {
        Self {
            group_name: name,
            proxy_names: proxies,
            test_url: hc.url,
            interval: Duration::from_secs(hc.interval_secs),
            expected_status: hc.expected_status,
            state_store,
            force_selected: parking_lot::RwLock::new(None),
            failed_times: AtomicU32::new(0),
            failed_time: parking_lot::Mutex::new(Instant::now()),
            failed_testing: AtomicBool::new(false),
            max_failed_times: hc.max_failed_times.unwrap_or(5),
            test_timeout: hc.test_timeout.unwrap_or(5000),
            last_touch: Arc::new(AtomicU64::new(0)),
            lazy: hc.lazy,
            health_notify: Arc::new(Notify::new()),
        }
    }

    /// Mark whether a triggered health check is currently running.
    /// mihomo compat: `failedTesting` flag in groupbase.go.
    pub(crate) fn set_health_testing(&self, running: bool) {
        self.failed_testing.store(running, Ordering::Relaxed);
        if !running {
            self.failed_times.store(0, Ordering::Relaxed);
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    #[allow(dead_code)]
    pub fn test_url(&self) -> &str {
        &self.test_url
    }

    /// Get a reference to the state store (for API reporting).
    #[allow(dead_code)]
    pub fn state_store(&self) -> &Arc<ProxyStateStore> {
        &self.state_store
    }

    /// Run a health check against all proxies concurrently through their
    /// actual proxy connections, matching mihomo's behavior.
    pub async fn health_check(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        super::health::run_health_check(
            "fallback",
            &self.proxy_names,
            &self.test_url,
            self.test_timeout,
            self.expected_status.clone(),
            proxies,
            dns,
            &self.state_store,
        )
        .await;
    }

    /// mihomo compat: fallback.go findAliveProxy — walk the list in config
    /// order. A pinned proxy is honored only while alive; when its entry is
    /// found dead the pin is CLEARED and the remaining proxies are scanned
    /// for the first alive one. Falls back to the first proxy.
    fn find_alive_proxy(&self) -> Option<String> {
        let mut selected = self.force_selected.write();
        for name in &self.proxy_names {
            match selected.as_deref() {
                None => {
                    if self.state_store.alive_for_url(name, &self.test_url) {
                        return Some(name.clone());
                    }
                }
                Some(sel) => {
                    if name == sel {
                        if self.state_store.alive_for_url(name, &self.test_url) {
                            return Some(name.clone());
                        }
                        *selected = None;
                    }
                }
            }
        }
        self.proxy_names.first().cloned()
    }

    /// Get alive proxies with their delays (for API reporting).
    #[allow(dead_code)]
    pub fn get_alive(&self) -> HashMap<String, u64> {
        let mut result = HashMap::new();
        for name in &self.proxy_names {
            if self.state_store.alive_for_url(name, &self.test_url) {
                let delay = self.state_store.last_delay_for_url(name, &self.test_url);
                if delay != 0xFFFF {
                    result.insert(name.clone(), delay as u64);
                }
            }
        }
        result
    }

    /// Trigger an immediate health check via the background loop.
    /// mihomo compat: matches GroupBase.healthCheck() in groupbase.go.
    fn do_health_check(&self) {
        if self.failed_testing.load(Ordering::Relaxed) {
            return;
        }
        self.health_notify.notify_one();
    }
}

impl ProxyGroup for FallbackGroup {
    fn name(&self) -> &str {
        &self.group_name
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
        self.proxy_names.clone()
    }

    fn select(&self, name: &str) -> bool {
        // mihomo compat: Fallback supports force-pinning via Set/ForceSet.
        if self.proxy_names.iter().any(|n| n == name) {
            *self.force_selected.write() = Some(name.to_string());
            // TODO: mihomo fallback.go Set() (fallback.go:124-146) fires a
            // one-shot URLTest with a 5s timeout against just the newly
            // pinned proxy when it is not alive. select() has no access to
            // the proxies map / DNS resolver here, so we trigger the group's
            // health-check loop instead, which re-probes all members.
            if !self.state_store.alive_for_url(name, &self.test_url) {
                self.health_notify.notify_one();
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
        for name in &self.proxy_names {
            if let Some(handler) = proxies.get(name) {
                return Some(handler.clone());
            }
        }
        None
    }

    /// mihomo compat: GroupBase.onDialFailed() in groupbase.go
    fn on_dial_failed(&self, proxy_type: &str, err: &str) {
        // mihomo compat: skip for built-in adapter types
        match proxy_type {
            "Direct" | "Compatible" | "Reject" | "Pass" | "RejectDrop" => return,
            _ => {}
        }

        // mihomo compat: "connection refused" triggers immediate health check
        if err.contains("connection refused") {
            self.do_health_check();
            return;
        }

        let mut failed_time = self.failed_time.lock();
        let prev = self.failed_times.fetch_add(1, Ordering::Relaxed);
        if prev == 0 {
            // First failure
            debug!("ProxyGroup: {} first failed", self.group_name);
            *failed_time = Instant::now();
        } else {
            // Check if within test_timeout window
            if failed_time.elapsed() > Duration::from_millis(self.test_timeout) {
                self.failed_times.store(0, Ordering::Relaxed);
                return;
            }
            let count = prev + 1;
            debug!("ProxyGroup: {} failed count: {}", self.group_name, count);
            if count >= self.max_failed_times {
                warn!(
                    "because {} failed multiple times, activate health check",
                    self.group_name
                );
                self.do_health_check();
            }
        }
    }

    /// mihomo compat: GroupBase.onDialSuccess() in groupbase.go
    fn on_dial_success(&self) {
        if !self.failed_testing.load(Ordering::Relaxed) {
            self.failed_times.store(0, Ordering::Relaxed);
        }
    }

    /// mihomo compat: GroupBase.Touch() in groupbase.go
    fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_touch.store(now, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(group.interval(), Duration::from_secs(600));
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
