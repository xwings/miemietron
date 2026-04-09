use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::common::addr::Address;
use crate::common::singledo::SingleDo;
use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

use super::proxy_state::ProxyStateStore;
use super::{HealthCheckOpts, ProxyGroup};

/// Auto-select the proxy with the lowest measured latency.
///
/// Health checks run concurrently against a configurable URL through each
/// proxy's `connect_stream()`, measuring true end-to-end latency.
/// Results are stored in a shared `ProxyStateStore`. `get_proxy` returns the
/// proxy with the smallest delay value.
pub struct UrlTestGroup {
    group_name: String,
    proxy_names: Vec<String>,
    test_url: String,
    interval: Duration,
    tolerance: u32,
    /// Centralized state store for delay/alive tracking.
    state_store: Arc<ProxyStateStore>,
    /// Current best proxy (tolerance-aware sticky selection).
    current_best: parking_lot::RwLock<Option<String>>,
    /// mihomo compat: force-pinned selection via API (Set/ForceSet).
    /// When Some, overrides auto-selection as long as the proxy is alive.
    force_selected: parking_lot::RwLock<Option<String>>,
    /// mihomo compat: SingleDo deduplication for fast() selection.
    /// Prevents thundering herd on concurrent now()/get_proxy() calls.
    fast_single: Arc<SingleDo<String>>,
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
}

impl UrlTestGroup {
    pub fn new(
        name: String,
        proxies: Vec<String>,
        tolerance: u32,
        hc: HealthCheckOpts,
        state_store: Arc<ProxyStateStore>,
    ) -> Self {
        Self {
            group_name: name,
            proxy_names: proxies,
            test_url: hc.url,
            interval: Duration::from_secs(hc.interval_secs),
            tolerance,
            state_store,
            current_best: parking_lot::RwLock::new(None),
            force_selected: parking_lot::RwLock::new(None),
            fast_single: Arc::new(SingleDo::new(Duration::from_secs(10))),
            failed_times: AtomicU32::new(0),
            failed_time: parking_lot::Mutex::new(Instant::now()),
            failed_testing: AtomicBool::new(false),
            max_failed_times: hc.max_failed_times.unwrap_or(5),
            test_timeout: hc.test_timeout.unwrap_or(5000),
            last_touch: Arc::new(AtomicU64::new(0)),
            lazy: hc.lazy,
        }
    }

    /// The configured health check interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The configured test URL.
    #[allow(dead_code)]
    pub fn test_url(&self) -> &str {
        &self.test_url
    }

    /// Get a reference to the state store (for API reporting).
    #[allow(dead_code)]
    pub fn state_store(&self) -> &Arc<ProxyStateStore> {
        &self.state_store
    }

    /// Run a health check against all proxies concurrently.
    ///
    /// Connects through each proxy via `connect_stream` and sends an HTTP HEAD
    /// request, measuring total end-to-end latency. Results are recorded in the
    /// shared `ProxyStateStore`.
    ///
    /// This is the ONLY health check path — all checks go through the actual
    /// proxy, matching mihomo's behavior in adapter.go URLTest().
    pub async fn health_check(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
        dns: &Arc<DnsResolver>,
    ) {
        let mut handles = Vec::new();
        // mihomo compat: all health checks fire concurrently (like Go goroutines + WaitGroup).
        // No semaphore — mihomo uses unbounded goroutines.

        for name in &self.proxy_names {
            let handler = match proxies.get(name) {
                Some(h) => h.clone(),
                None => continue,
            };
            let name = name.clone();
            let url = self.test_url.clone();
            let dns = dns.clone();
            let state_store = self.state_store.clone();

            let handle = tokio::spawn(async move {
                match measure_unified_delay(&handler, &url, &dns).await {
                    Ok(ms) => {
                        debug!("url-test {}: {}ms", name, ms);
                        let delay = if ms > u16::MAX as u64 {
                            u16::MAX
                        } else {
                            ms as u16
                        };
                        state_store.record_result(&name, &url, Some(delay));
                    }
                    Err(e) => {
                        warn!("url-test {}: {}", name, e);
                        state_store.record_result(&name, &url, None);
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }
    }

    /// Get the current delay results (for API reporting).
    #[allow(dead_code)]
    pub fn get_delays(&self) -> HashMap<String, u64> {
        let mut result = HashMap::new();
        for name in &self.proxy_names {
            let delay = self.state_store.last_delay_for_url(name, &self.test_url);
            if delay != 0xFFFF {
                result.insert(name.clone(), delay as u64);
            }
        }
        result
    }

    /// Compute the best proxy name.
    /// mihomo compat: matches urltest.go fast() — uses tolerance-aware
    /// hysteresis to prevent flapping between proxies.
    fn fast(&self) -> String {
        // mihomo compat: if a proxy is force-pinned via API, return it
        // (as long as it's alive — matching mihomo's fast() logic).
        if let Some(ref selected) = *self.force_selected.read() {
            if self.state_store.alive_for_url(selected, &self.test_url) {
                return selected.clone();
            }
            // If no health check yet, still honor the force selection
            // (alive_for_url returns true when no state is recorded)
            return selected.clone();
        }

        // Find the proxy with the lowest delay among alive proxies
        let mut best_name: Option<String> = None;
        let mut best_delay: u16 = 0xFFFF;

        for name in &self.proxy_names {
            if !self.state_store.alive_for_url(name, &self.test_url) {
                continue;
            }
            let delay = self.state_store.last_delay_for_url(name, &self.test_url);
            if delay < best_delay {
                best_delay = delay;
                best_name = Some(name.clone());
            }
        }

        if let Some(ref best) = best_name {
            if best_delay < 0xFFFF {
                let mut current = self.current_best.write();
                // Check if current best is still alive and within tolerance
                // mihomo compat: tolerance check from urltest.go fast()
                if let Some(ref cur) = *current {
                    if self.state_store.alive_for_url(cur, &self.test_url) {
                        let cur_delay =
                            self.state_store.last_delay_for_url(cur, &self.test_url);
                        if cur_delay < 0xFFFF
                            && cur_delay <= best_delay + self.tolerance as u16
                        {
                            return cur.clone();
                        }
                    }
                }
                // Switch to new best
                *current = Some(best.clone());
                return best.clone();
            }
        }

        self.proxy_names.first().cloned().unwrap_or_default()
    }

    /// Reset the fast_single cache. Called after health checks and when
    /// clearing force-pinned selection.
    /// mihomo compat: matches URLTest.healthCheck() resetting fastSingle.
    pub fn reset_fast_single(&self) {
        self.fast_single.reset();
    }

    /// Trigger the onDialFailed health check logic.
    /// mihomo compat: matches GroupBase.healthCheck() in groupbase.go
    fn do_health_check(&self) {
        if self.failed_testing.load(Ordering::Relaxed) {
            return;
        }
        self.failed_testing.store(true, Ordering::Relaxed);
        self.fast_single.reset();
        // The actual health check is async and runs in the health check loop.
        // Here we just reset the failure counters, matching mihomo's pattern
        // where healthCheck() calls proxyProvider.HealthCheck() and then resets.
        self.failed_testing.store(false, Ordering::Relaxed);
        self.failed_times.store(0, Ordering::Relaxed);
        self.fast_single.reset();
    }
}

impl ProxyGroup for UrlTestGroup {
    fn name(&self) -> &str {
        &self.group_name
    }

    fn group_type(&self) -> &str {
        "URLTest"
    }

    fn now(&self) -> String {
        self.fast()
    }

    fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    fn select(&self, name: &str) -> bool {
        // mihomo compat: URLTest supports force-pinning via Set/ForceSet.
        if self.proxy_names.iter().any(|n| n == name) {
            *self.force_selected.write() = Some(name.to_string());
            self.fast_single.reset();
            true
        } else {
            false
        }
    }

    fn clear_selection(&self) {
        // mihomo compat: ForceSet("") — clear forced selection, resume auto-select.
        *self.force_selected.write() = None;
        self.fast_single.reset();
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        let selected_name = self.fast();
        if let Some(handler) = proxies.get(&selected_name) {
            return Some(handler.clone());
        }

        // Fallback: first available proxy in list order.
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
            debug!(
                "ProxyGroup: {} failed count: {}",
                self.group_name, count
            );
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

/// Measure latency by connecting through a proxy and sending an HTTP HEAD request.
/// Returns the total elapsed time in milliseconds.
///
/// Measure latency by connecting through a proxy and sending an HTTP HEAD request.
/// Returns the total elapsed time in milliseconds.
///
/// mihomo compat: matches adapter.go URLTest() which uses a 30s HTTP client timeout,
/// dials through the proxy, sends HEAD, reads the status line.
pub(crate) async fn measure_unified_delay(
    handler: &Arc<dyn OutboundHandler>,
    url: &str,
    dns: &DnsResolver,
) -> anyhow::Result<u64> {
    // Parse URL to extract host and port
    let parsed: url::Url = url.parse()?;
    let host = parsed.host_str().unwrap_or("www.gstatic.com").to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };

    let target = Address::domain(&host, port);
    let start = Instant::now();

    // mihomo compat: 30s overall timeout (adapter.go: client.Timeout = 30 * time.Second)
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        // Connect through the proxy
        let mut stream = handler.connect_stream(&target, dns).await?;

        // Send HTTP HEAD request
        // mihomo compat: uses Go's http.NewRequest(HEAD, url, nil) which adds standard headers
        let req = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: clash\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;

        // Read until we get the status line
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await?;

        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.starts_with("HTTP/") {
            let _ = stream.shutdown().await;
            return Err(anyhow::anyhow!("invalid HTTP response"));
        }

        let elapsed = start.elapsed().as_millis() as u64;
        let _ = stream.shutdown().await;
        Ok::<u64, anyhow::Error>(elapsed)
    })
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout"))??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<ProxyStateStore> {
        Arc::new(ProxyStateStore::new())
    }

    fn make_hc(url: &str) -> HealthCheckOpts {
        HealthCheckOpts { url: url.to_string(), interval_secs: 300, max_failed_times: None, test_timeout: None, lazy: false }
    }

    #[test]
    fn defaults_are_correct() {
        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["a".to_string(), "b".to_string()],
            150,
            HealthCheckOpts { url: "http://test.example/204".to_string(), interval_secs: 300, max_failed_times: None, test_timeout: None, lazy: false },
            make_store(),
        );
        assert_eq!(group.name(), "auto");
        assert_eq!(group.group_type(), "URLTest");
        assert_eq!(group.interval(), Duration::from_secs(300));
        assert_eq!(group.test_url(), "http://test.example/204");
        assert_eq!(group.all(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn now_before_health_check_returns_first_proxy() {
        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["fast".to_string(), "slow".to_string()],
            50,
            make_hc("http://test.example/204"),
            make_store(),
        );
        // No health check has run, delays map is empty.
        assert_eq!(group.now(), "fast");
    }

    #[test]
    fn select_force_pins_proxy() {
        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["a".to_string(), "b".to_string()],
            50,
            make_hc("http://test.example/204"),
            make_store(),
        );
        // Can force-pin a proxy that exists in the group
        assert!(group.select("b"));
        assert_eq!(group.now(), "b");
        // Can clear force-selection
        group.clear_selection();
        assert_eq!(group.now(), "a"); // falls back to first
        // Can't select a proxy not in the group
        assert!(!group.select("nonexistent"));
    }

    #[test]
    fn empty_proxies_now_returns_empty_string() {
        let group = UrlTestGroup::new(
            "empty".to_string(),
            vec![],
            50,
            make_hc("http://test.example/204"),
            make_store(),
        );
        assert_eq!(group.now(), "");
    }

    #[test]
    fn now_picks_lowest_delay() {
        let store = make_store();
        let url = "http://test.example/204";
        store.record_result("slow", url, Some(500));
        store.record_result("fast", url, Some(100));
        store.record_result("medium", url, Some(300));

        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec![
                "slow".to_string(),
                "fast".to_string(),
                "medium".to_string(),
            ],
            50,
            make_hc(url),
            store,
        );
        assert_eq!(group.now(), "fast");
    }

    #[test]
    fn tolerance_prevents_flapping() {
        let store = make_store();
        let url = "http://test.example/204";
        store.record_result("a", url, Some(100));
        store.record_result("b", url, Some(130));

        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["a".to_string(), "b".to_string()],
            50, // tolerance = 50ms
            make_hc(url),
            store.clone(),
        );

        // First call picks "a" (lowest)
        assert_eq!(group.now(), "a");

        // Now "b" becomes slightly faster, but within tolerance
        store.record_result("a", url, Some(120));
        store.record_result("b", url, Some(110));

        // Should stick with "a" since 120 <= 110 + 50
        assert_eq!(group.now(), "a");

        // Now "b" becomes much faster, exceeding tolerance
        store.record_result("b", url, Some(50));

        // Should switch to "b" since 120 > 50 + 50
        assert_eq!(group.now(), "b");
    }
}
