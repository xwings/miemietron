//! Centralized per-proxy, per-test-URL state store.
//!
//! Matches mihomo's per-proxy `extra` map from `adapter/adapter.go`.
//! Each proxy has a default state (primary test URL) and optional per-URL
//! state for groups that use different test URLs.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;

use crate::common::delay_history::{DelayHistory, ProxyState};

/// Centralized per-proxy, per-test-URL state store.
/// Matches mihomo's per-proxy `extra` map from `adapter/adapter.go`.
pub struct ProxyStateStore {
    /// proxy_name -> default state (for the primary test URL)
    default_state: DashMap<String, Arc<ProxyState>>,
    /// (proxy_name, test_url) -> per-URL state
    extra_state: DashMap<(String, String), Arc<ProxyState>>,
}

impl ProxyStateStore {
    pub fn new() -> Self {
        Self {
            default_state: DashMap::new(),
            extra_state: DashMap::new(),
        }
    }

    /// Records a delay measurement or failure.
    /// Updates both default and per-URL state.
    /// If delay is Some, alive=true. If None, alive=false, delay=0.
    ///
    /// Matches mihomo's adapter.go URLTest() result recording pattern.
    pub fn record_result(&self, proxy: &str, url: &str, delay: Option<u16>) {
        let (alive, delay_val) = match delay {
            Some(d) => (true, d),
            None => (false, 0),
        };

        // Update default state
        let state = self
            .default_state
            .entry(proxy.to_string())
            .or_insert_with(|| Arc::new(ProxyState::new()))
            .clone();
        state.set_alive(alive);
        state.history.put(DelayHistory {
            time: Utc::now(),
            delay: delay_val,
        });

        // Update per-URL state
        let url_state = self
            .extra_state
            .entry((proxy.to_string(), url.to_string()))
            .or_insert_with(|| Arc::new(ProxyState::new()))
            .clone();
        url_state.set_alive(alive);
        url_state.history.put(DelayHistory {
            time: Utc::now(),
            delay: delay_val,
        });
    }

    /// Records a probe that succeeded but returned an HTTP status outside the
    /// expected-status ranges.
    ///
    /// mihomo compat: adapter.go URLTest() defer (adapter.go:166-200) — when
    /// the request succeeds but `satisfied` is false, the DEFAULT state stays
    /// alive and records the real delay, while only the per-URL extra state
    /// records delay=0 and alive=false.
    pub fn record_unexpected_status(&self, proxy: &str, url: &str, delay: u16) {
        let state = self
            .default_state
            .entry(proxy.to_string())
            .or_insert_with(|| Arc::new(ProxyState::new()))
            .clone();
        state.set_alive(true);
        state.history.put(DelayHistory {
            time: Utc::now(),
            delay,
        });

        let url_state = self
            .extra_state
            .entry((proxy.to_string(), url.to_string()))
            .or_insert_with(|| Arc::new(ProxyState::new()))
            .clone();
        url_state.set_alive(false);
        url_state.history.put(DelayHistory {
            time: Utc::now(),
            delay: 0,
        });
    }

    /// Check if a proxy is alive for a specific test URL.
    /// Checks per-URL state first, falls back to default.
    /// Returns true if no state recorded yet (matching mihomo).
    pub fn alive_for_url(&self, proxy: &str, url: &str) -> bool {
        // Check per-URL state first
        if let Some(state) = self.extra_state.get(&(proxy.to_string(), url.to_string())) {
            return state.is_alive();
        }
        // Fall back to default state
        if let Some(state) = self.default_state.get(proxy) {
            return state.is_alive();
        }
        // No state recorded yet — assume alive (mihomo compat)
        true
    }

    /// Returns delay for a proxy+URL, or 0xFFFF if dead/unknown.
    /// mihomo compat: adapter.go:118-133 LastDelayForTestUrl reads ONLY the
    /// per-URL extra state — it never falls back to the default-state history
    /// (absent extra state means alive=false → 0xFFFF).
    pub fn last_delay_for_url(&self, proxy: &str, url: &str) -> u16 {
        if let Some(state) = self.extra_state.get(&(proxy.to_string(), url.to_string())) {
            if !state.is_alive() {
                return 0xFFFF;
            }
            if let Some(last) = state.history.last() {
                if last.delay > 0 {
                    return last.delay;
                }
            }
        }
        0xFFFF
    }

    /// Default URL history for a proxy (for API reporting).
    pub fn delay_history(&self, proxy: &str) -> Vec<DelayHistory> {
        if let Some(state) = self.default_state.get(proxy) {
            state.history.copy()
        } else {
            Vec::new()
        }
    }

    /// Per-URL state for API reporting.
    /// Returns a map of test_url -> { alive, history } for all URLs
    /// this proxy has been tested against.
    ///
    /// Matches mihomo's `extra` field in proxy API responses.
    pub fn extra_delay_histories(&self, proxy: &str) -> HashMap<String, serde_json::Value> {
        let mut result = HashMap::new();
        let proxy_str = proxy.to_string();

        for entry in self.extra_state.iter() {
            let (ref pname, ref url) = *entry.key();
            if pname == &proxy_str {
                let state = entry.value();
                let history: Vec<serde_json::Value> = state
                    .history
                    .copy()
                    .into_iter()
                    .map(|h| {
                        serde_json::json!({
                            "time": h.time.to_rfc3339(),
                            "delay": h.delay,
                        })
                    })
                    .collect();
                result.insert(
                    url.clone(),
                    serde_json::json!({
                        "alive": state.is_alive(),
                        "history": history,
                    }),
                );
            }
        }

        result
    }
}

impl Default for ProxyStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_proxy_assumed_alive() {
        let store = ProxyStateStore::new();
        assert!(store.alive_for_url("proxy1", "http://test.example/204"));
        assert_eq!(
            store.last_delay_for_url("proxy1", "http://test.example/204"),
            0xFFFF
        );
    }

    #[test]
    fn test_record_success() {
        let store = ProxyStateStore::new();
        store.record_result("proxy1", "http://test.example/204", Some(150));

        assert!(store.alive_for_url("proxy1", "http://test.example/204"));
        assert_eq!(
            store.last_delay_for_url("proxy1", "http://test.example/204"),
            150
        );
    }

    #[test]
    fn test_record_failure() {
        let store = ProxyStateStore::new();
        // Record a success first
        store.record_result("proxy1", "http://test.example/204", Some(100));
        assert!(store.alive_for_url("proxy1", "http://test.example/204"));

        // Then record a failure
        store.record_result("proxy1", "http://test.example/204", None);
        assert!(!store.alive_for_url("proxy1", "http://test.example/204"));
        assert_eq!(
            store.last_delay_for_url("proxy1", "http://test.example/204"),
            0xFFFF
        );
    }

    #[test]
    fn test_per_url_state_isolation() {
        let store = ProxyStateStore::new();
        store.record_result("proxy1", "http://url-a/204", Some(100));
        store.record_result("proxy1", "http://url-b/204", None);

        assert!(store.alive_for_url("proxy1", "http://url-a/204"));
        assert!(!store.alive_for_url("proxy1", "http://url-b/204"));
        assert_eq!(store.last_delay_for_url("proxy1", "http://url-a/204"), 100);
        assert_eq!(
            store.last_delay_for_url("proxy1", "http://url-b/204"),
            0xFFFF
        );
    }

    #[test]
    fn test_delay_history() {
        let store = ProxyStateStore::new();
        store.record_result("proxy1", "http://test/204", Some(100));
        store.record_result("proxy1", "http://test/204", Some(150));
        store.record_result("proxy1", "http://test/204", Some(200));

        let history = store.delay_history("proxy1");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].delay, 100);
        assert_eq!(history[1].delay, 150);
        assert_eq!(history[2].delay, 200);
    }

    #[test]
    fn test_extra_delay_histories() {
        let store = ProxyStateStore::new();
        store.record_result("proxy1", "http://url-a/204", Some(100));
        store.record_result("proxy1", "http://url-b/204", Some(200));

        let extras = store.extra_delay_histories("proxy1");
        assert_eq!(extras.len(), 2);
        assert!(extras.contains_key("http://url-a/204"));
        assert!(extras.contains_key("http://url-b/204"));
    }

    #[test]
    fn test_record_unexpected_status() {
        // mihomo compat: adapter.go URLTest — unexpected status keeps the
        // default state alive with the real delay; the per-URL extra state
        // goes dead with delay 0.
        let store = ProxyStateStore::new();
        store.record_unexpected_status("proxy1", "http://test/204", 150);

        // Default state: alive, real delay recorded
        let history = store.delay_history("proxy1");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].delay, 150);

        // Per-URL extra state: dead, delay 0
        assert!(!store.alive_for_url("proxy1", "http://test/204"));
        assert_eq!(
            store.last_delay_for_url("proxy1", "http://test/204"),
            0xFFFF
        );
        let extras = store.extra_delay_histories("proxy1");
        let extra = &extras["http://test/204"];
        assert_eq!(extra["alive"], serde_json::json!(false));
        assert_eq!(extra["history"][0]["delay"], serde_json::json!(0));
    }

    #[test]
    fn test_last_delay_no_default_fallback() {
        // mihomo compat: LastDelayForTestUrl reads only per-URL extra state.
        let store = ProxyStateStore::new();
        store.record_result("proxy1", "http://url-a/204", Some(100));
        // Different URL: no extra state → 0xFFFF even though default exists.
        assert_eq!(
            store.last_delay_for_url("proxy1", "http://url-b/204"),
            0xFFFF
        );
    }

    #[test]
    fn test_unknown_proxy_history() {
        let store = ProxyStateStore::new();
        let history = store.delay_history("nonexistent");
        assert!(history.is_empty());
        let extras = store.extra_delay_histories("nonexistent");
        assert!(extras.is_empty());
    }
}
