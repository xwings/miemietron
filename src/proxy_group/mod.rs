mod fallback;
pub mod health;
mod load_balance;
pub mod proxy_state;
mod selector;
mod url_test;

pub use fallback::FallbackGroup;
pub use load_balance::{LoadBalanceGroup, LoadBalanceStrategy};
pub use selector::SelectorGroup;
pub use url_test::UrlTestGroup;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tracing::{debug, warn};

use self::proxy_state::ProxyStateStore;
use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

/// Health check options shared by URLTest, Fallback, LoadBalance and
/// (optionally) Selector groups.
pub struct HealthCheckOpts {
    pub url: String,
    pub interval_secs: u64,
    pub max_failed_times: Option<u32>,
    pub test_timeout: Option<u64>,
    pub lazy: bool,
    /// Parsed `expected-status` ranges. `None` matches any status ("*").
    pub expected_status: Option<Vec<(u16, u16)>>,
}

/// Parse an `expected-status` string into status ranges.
/// mihomo compat: utils.NewUnsignedRanges (common/utils/ranges.go) —
/// empty/"*" means any status (None); "," is normalized to "/"; each segment
/// is a single status or `lo-hi` range (reversed bounds are swapped, not an
/// error); more than 28 ranges or a malformed segment is an error.
pub fn parse_expected_status(s: &str) -> Result<Option<Vec<(u16, u16)>>, String> {
    let s = s.trim();
    if s.is_empty() || s == "*" {
        return Ok(None);
    }
    let normalized = s.replace(',', "/");
    let list: Vec<&str> = normalized.split('/').collect();
    if list.len() > 28 {
        return Err("intRanges error, too many ranges to use, maximum support 28 ranges".into());
    }
    let mut ranges = Vec::new();
    for part in list {
        if part.is_empty() {
            continue;
        }
        let part = part.trim();
        let status: Vec<&str> = part.split('-').collect();
        let parse = |v: &str| -> Result<u16, String> {
            v.trim_matches(|c: char| c == '[' || c == ']' || c == ' ')
                .parse::<u16>()
                .map_err(|_| format!("invalid range: {part}"))
        };
        match status.len() {
            1 => {
                let v = parse(status[0])?;
                ranges.push((v, v));
            }
            2 => {
                let lo = parse(status[0])?;
                let hi = parse(status[1])?;
                // mihomo compat: NewRange swaps reversed bounds
                if lo <= hi {
                    ranges.push((lo, hi));
                } else {
                    ranges.push((hi, lo));
                }
            }
            _ => return Err(format!("invalid range: {part}")),
        }
    }
    if ranges.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ranges))
    }
}

/// Check a status code against parsed expected-status ranges.
/// mihomo compat: utils.IntRanges.Check — empty ranges match everything.
pub fn status_matches(code: u16, ranges: &[(u16, u16)]) -> bool {
    if ranges.is_empty() {
        return true;
    }
    ranges.iter().any(|&(lo, hi)| code >= lo && code <= hi)
}

/// State and behavior shared by the URLTest, Fallback and LoadBalance groups.
///
/// mihomo compat: adapter/outboundgroup/groupbase.go GroupBase — same field
/// set (name, member list, test URL, interval, failure tracking, lazy
/// `lastTouch`) and same `Touch` / `onDialSuccess` / `onDialFailed` /
/// `healthCheck` semantics. `SelectorGroup` deliberately does NOT use it:
/// mihomo's Selector has no onDial hooks and carries its health-check state
/// only when the user configured an interval.
pub(crate) struct GroupBase {
    group_name: String,
    proxy_names: Vec<String>,
    test_url: String,
    interval: Duration,
    /// mihomo compat: expected-status ranges for the health check.
    expected_status: Option<Vec<(u16, u16)>>,
    /// Centralized state store for delay/alive tracking.
    state_store: Arc<ProxyStateStore>,
    /// mihomo compat: onDialFailed tracking fields.
    failed_times: AtomicU32,
    failed_time: parking_lot::Mutex<Instant>,
    failed_testing: AtomicBool,
    max_failed_times: u32,
    test_timeout: u64,
    /// mihomo compat: lazy health check — tracks when group was last used.
    /// Epoch millis.
    last_touch: Arc<AtomicU64>,
    /// Whether this group uses lazy health checks.
    lazy: bool,
    /// mihomo compat: failure-driven health check trigger.
    /// `do_health_check` calls `notify_one()`; the background loop in
    /// `health.rs` wakes and runs an immediate check, matching
    /// GroupBase.healthCheck() in groupbase.go.
    health_notify: Arc<Notify>,
}

impl GroupBase {
    pub(crate) fn new(
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

    pub(crate) fn name(&self) -> &str {
        &self.group_name
    }

    pub(crate) fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.proxy_names.iter().any(|n| n == name)
    }

    pub(crate) fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    pub(crate) fn test_url(&self) -> &str {
        &self.test_url
    }

    /// The configured health check interval.
    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }

    /// Whether this group uses lazy health checks.
    pub(crate) fn lazy(&self) -> bool {
        self.lazy
    }

    /// Epoch millis of the last `touch()`, or 0 if never touched.
    pub(crate) fn last_touch_millis(&self) -> u64 {
        self.last_touch.load(Ordering::Relaxed)
    }

    pub(crate) fn health_notify(&self) -> Arc<Notify> {
        self.health_notify.clone()
    }

    pub(crate) fn state_store(&self) -> &Arc<ProxyStateStore> {
        &self.state_store
    }

    /// Whether `name` is alive for this group's test URL.
    pub(crate) fn alive(&self, name: &str) -> bool {
        self.state_store.alive_for_url(name, &self.test_url)
    }

    /// Run a health check against all members concurrently through their
    /// actual proxy connections, matching mihomo's behavior. `kind` is the
    /// group-type label used in the per-proxy log lines.
    pub(crate) async fn run_health_check(
        &self,
        kind: &str,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        health::run_health_check(
            kind,
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

    /// Mark whether a triggered health check is currently running.
    /// mihomo compat: `failedTesting` flag in groupbase.go controls whether
    /// `onDialSuccess` resets the failure counter.
    pub(crate) fn set_health_testing(&self, running: bool) {
        self.failed_testing.store(running, Ordering::Relaxed);
        if !running {
            self.failed_times.store(0, Ordering::Relaxed);
        }
    }

    /// Trigger an immediate health check via the background loop.
    /// mihomo compat: matches GroupBase.healthCheck() in groupbase.go —
    /// signals the health.rs loop to run a fresh pass instead of waiting for
    /// the next periodic tick.
    pub(crate) fn do_health_check(&self) {
        if self.failed_testing.load(Ordering::Relaxed) {
            return;
        }
        self.health_notify.notify_one();
    }

    /// mihomo compat: GroupBase.onDialFailed() in groupbase.go. `trigger` is
    /// the owning group's health-check trigger — URLTest wraps the base one to
    /// also drop its `fastSingle` cache (urltest.go:213).
    pub(crate) fn on_dial_failed(&self, proxy_type: &str, err: &str, trigger: impl Fn()) {
        // mihomo compat: skip for built-in adapter types
        match proxy_type {
            "Direct" | "Compatible" | "Reject" | "Pass" | "RejectDrop" => return,
            _ => {}
        }

        // mihomo compat: "connection refused" triggers immediate health check
        if err.contains("connection refused") {
            trigger();
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
                trigger();
            }
        }
    }

    /// mihomo compat: GroupBase.onDialSuccess() in groupbase.go
    pub(crate) fn on_dial_success(&self) {
        if !self.failed_testing.load(Ordering::Relaxed) {
            self.failed_times.store(0, Ordering::Relaxed);
        }
    }

    /// mihomo compat: GroupBase.Touch() in groupbase.go
    pub(crate) fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_touch.store(now, Ordering::Relaxed);
    }
}

/// Trait implemented by all proxy group types.
pub trait ProxyGroup: Send + Sync {
    /// The display name of this group.
    fn name(&self) -> &str;

    /// The group type string (e.g. "Selector", "URLTest").
    fn group_type(&self) -> &str;

    /// The currently selected/active proxy name.
    fn now(&self) -> String;

    /// All proxy names in this group.
    fn all(&self) -> Vec<String>;

    /// Manually select a proxy by name. Returns true if the proxy exists in the group.
    /// For Selector: normal selection. For URLTest/Fallback: force-pin (mihomo compat).
    fn select(&self, name: &str) -> bool;

    /// Clear a force-pinned selection (mihomo compat: ForceSet("")).
    /// Only meaningful for URLTest/Fallback. Selector groups ignore this.
    fn clear_selection(&self) {}

    /// The force-pinned proxy name for URLTest/Fallback groups (mihomo's
    /// `fixed` JSON field — urltest.go:181 / fallback.go:90). Empty when
    /// unpinned or for group types without force-pinning.
    fn fixed(&self) -> String {
        String::new()
    }

    /// Resolve the group to a concrete outbound handler using the proxy map.
    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>>;

    /// Called when a connection through this group's proxy fails.
    /// mihomo compat: matches GroupBase.onDialFailed() in groupbase.go
    fn on_dial_failed(&self, _proxy_type: &str, _err: &str) {}

    /// Called when a connection through this group's proxy succeeds.
    /// mihomo compat: matches GroupBase.onDialSuccess() in groupbase.go
    fn on_dial_success(&self) {}

    /// Touch the group to mark it as recently used (for lazy health checks).
    /// mihomo compat: matches GroupBase.Touch() in groupbase.go
    fn touch(&self) {}

    /// Upcast to `Any` for safe downcasting to the concrete group type
    /// (used by health.rs to wire background health checks).
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync>;
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn make_base() -> GroupBase {
        GroupBase::new(
            "grp".to_string(),
            vec!["a".to_string(), "b".to_string()],
            HealthCheckOpts {
                url: "http://test.example/204".to_string(),
                interval_secs: 300,
                max_failed_times: None,
                test_timeout: None,
                lazy: false,
                expected_status: None,
            },
            Arc::new(ProxyStateStore::new()),
        )
    }

    #[test]
    fn defaults_match_mihomo() {
        // mihomo compat: healthcheck.go:202 test timeout 5000ms and
        // groupbase.go maxFailedTimes 5.
        let base = make_base();
        assert_eq!(base.name(), "grp");
        assert_eq!(base.test_url(), "http://test.example/204");
        assert_eq!(base.interval(), Duration::from_secs(300));
        assert_eq!(base.all(), vec!["a".to_string(), "b".to_string()]);
        assert!(base.contains("b"));
        assert!(!base.contains("c"));
        assert_eq!(base.max_failed_times, 5);
        assert_eq!(base.test_timeout, 5000);
        assert_eq!(base.last_touch_millis(), 0);
    }

    #[test]
    fn on_dial_failed_skips_builtin_adapter_types() {
        // mihomo compat: groupbase.go onDialFailed() returns early for the
        // built-in adapters, so they never arm the health check.
        let base = make_base();
        let fired = Cell::new(0u32);
        for kind in ["Direct", "Compatible", "Reject", "Pass", "RejectDrop"] {
            base.on_dial_failed(kind, "connection refused", || fired.set(fired.get() + 1));
        }
        assert_eq!(fired.get(), 0);
    }

    #[test]
    fn connection_refused_triggers_the_check_immediately() {
        // mihomo compat: groupbase.go onDialFailed() — "connection refused"
        // bypasses the failure counter entirely.
        let base = make_base();
        let fired = Cell::new(0u32);
        base.on_dial_failed("Shadowsocks", "dial tcp: connection refused", || {
            fired.set(fired.get() + 1)
        });
        assert_eq!(fired.get(), 1);
    }

    #[test]
    fn other_errors_trigger_only_at_max_failed_times() {
        // mihomo compat: groupbase.go onDialFailed() — the first failure only
        // stamps failedTime; the trigger fires once the count reaches
        // maxFailedTimes (5) inside the testTimeout window.
        let base = make_base();
        let fired = Cell::new(0u32);
        let bump = || fired.set(fired.get() + 1);
        for _ in 0..4 {
            base.on_dial_failed("Vmess", "i/o timeout", bump);
        }
        assert_eq!(fired.get(), 0, "must not fire before maxFailedTimes");
        base.on_dial_failed("Vmess", "i/o timeout", bump);
        assert_eq!(fired.get(), 1);
    }

    #[test]
    fn on_dial_success_resets_the_counter_unless_a_check_is_running() {
        // mihomo compat: groupbase.go onDialSuccess() is gated on
        // !failedTesting, so probe traffic during a triggered check cannot
        // clear the failures that armed it.
        let base = make_base();
        let fired = Cell::new(0u32);
        let bump = || fired.set(fired.get() + 1);

        for _ in 0..4 {
            base.on_dial_failed("Vmess", "i/o timeout", bump);
        }
        base.on_dial_success();
        // Counter cleared: the next failure is a "first failure" again.
        base.on_dial_failed("Vmess", "i/o timeout", bump);
        assert_eq!(fired.get(), 0);

        // With a triggered check running, on_dial_success is a no-op.
        base.set_health_testing(true);
        for _ in 0..3 {
            base.on_dial_success();
            base.on_dial_failed("Vmess", "i/o timeout", bump);
        }
        base.on_dial_failed("Vmess", "i/o timeout", bump);
        assert_eq!(fired.get(), 1);
    }

    #[test]
    fn clearing_health_testing_resets_the_failure_counter() {
        let base = make_base();
        let fired = Cell::new(0u32);
        let bump = || fired.set(fired.get() + 1);
        for _ in 0..4 {
            base.on_dial_failed("Vmess", "i/o timeout", bump);
        }
        base.set_health_testing(true);
        base.set_health_testing(false);
        // Counter zeroed, so five more failures are needed to fire again.
        for _ in 0..4 {
            base.on_dial_failed("Vmess", "i/o timeout", bump);
        }
        assert_eq!(fired.get(), 0);
        base.on_dial_failed("Vmess", "i/o timeout", bump);
        assert_eq!(fired.get(), 1);
    }

    #[tokio::test]
    async fn do_health_check_is_suppressed_while_a_check_is_running() {
        // mihomo compat: groupbase.go healthCheck() returns early when
        // failedTesting is already set, so a triggered pass is never
        // re-entered.
        let base = make_base();
        let notify = base.health_notify();

        base.set_health_testing(true);
        base.do_health_check();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), notify.notified())
                .await
                .is_err(),
            "no permit should be stored while a check is running"
        );

        base.set_health_testing(false);
        base.do_health_check();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), notify.notified())
                .await
                .is_ok(),
            "the loop must be woken once the running check clears"
        );
    }

    #[test]
    fn touch_records_epoch_millis() {
        let base = make_base();
        base.touch();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let touched = base.last_touch_millis();
        assert!(touched > 0);
        assert!(now.saturating_sub(touched) < 5_000);
    }

    #[test]
    fn alive_defaults_to_true_before_the_first_health_check() {
        // A group with no recorded results must not treat every member as
        // dead, or a fresh start would route nowhere.
        let base = make_base();
        assert!(base.alive("a"));
        base.state_store().record_result("a", base.test_url(), None);
        assert!(!base.alive("a"));
    }
}
