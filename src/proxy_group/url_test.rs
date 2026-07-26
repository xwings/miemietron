use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::addr::Address;
use crate::common::singledo::SingleDo;
use crate::dns::DnsResolver;
use crate::proxy::OutboundHandler;

use super::proxy_state::ProxyStateStore;
use super::{GroupBase, HealthCheckOpts, ProxyGroup};

/// Auto-select the proxy with the lowest measured latency.
///
/// Health checks run concurrently against a configurable URL through each
/// proxy's `connect_stream()`, measuring true end-to-end latency.
/// Results are stored in a shared `ProxyStateStore`. `get_proxy` returns the
/// proxy with the smallest delay value.
pub struct UrlTestGroup {
    /// mihomo compat: the embedded GroupBase (groupbase.go).
    base: GroupBase,
    tolerance: u32,
    /// Current best proxy (tolerance-aware sticky selection).
    current_best: parking_lot::RwLock<Option<String>>,
    /// mihomo compat: force-pinned selection via API (Set/ForceSet).
    /// When Some, overrides auto-selection as long as the proxy is alive.
    force_selected: parking_lot::RwLock<Option<String>>,
    /// mihomo compat: SingleDo deduplication for fast() selection.
    /// Prevents thundering herd on concurrent now()/get_proxy() calls.
    fast_single: Arc<SingleDo<String>>,
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
            base: GroupBase::new(name, proxies, hc, state_store),
            tolerance,
            current_best: parking_lot::RwLock::new(None),
            force_selected: parking_lot::RwLock::new(None),
            fast_single: Arc::new(SingleDo::new(Duration::from_secs(10))),
        }
    }

    pub(crate) fn base(&self) -> &GroupBase {
        &self.base
    }

    /// The configured test URL.
    #[cfg(test)]
    pub fn test_url(&self) -> &str {
        self.base.test_url()
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
        self.base.run_health_check("url-test", proxies, dns).await;
    }

    /// Compute the best proxy name.
    /// mihomo compat: matches urltest.go fast() — uses tolerance-aware
    /// hysteresis to prevent flapping between proxies, and `fastSingle`
    /// (10s) singleflight to dedupe concurrent callers.
    fn fast(&self) -> String {
        let (val, _shared) = self.fast_single.do_sync(|| self.compute_fast());
        val
    }

    fn compute_fast(&self) -> String {
        // mihomo compat: urltest.go fast() (urltest.go:110-120) — a
        // force-pinned proxy is only returned while alive for the test URL;
        // a dead pin falls through to fastest-alive selection WITHOUT
        // clearing `selected`, so the pin resumes when the proxy comes back
        // alive. (alive_for_url returns true when no state is recorded, so
        // a fresh pin is honored before the first health check.)
        if let Some(ref selected) = *self.force_selected.read() {
            if self.base.contains(selected) && self.base.alive(selected) {
                return selected.clone();
            }
        }

        let store = self.base.state_store();
        let test_url = self.base.test_url();

        // Find the proxy with the lowest delay among alive proxies
        let mut best_name: Option<String> = None;
        let mut best_delay: u16 = 0xFFFF;

        for name in self.base.proxy_names() {
            if !self.base.alive(name) {
                continue;
            }
            let delay = store.last_delay_for_url(name, test_url);
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
                    if self.base.alive(cur) {
                        let cur_delay = store.last_delay_for_url(cur, test_url);
                        if cur_delay < 0xFFFF && cur_delay <= best_delay + self.tolerance as u16 {
                            return cur.clone();
                        }
                    }
                }
                // Switch to new best
                *current = Some(best.clone());
                return best.clone();
            }
        }

        self.base.proxy_names().first().cloned().unwrap_or_default()
    }

    /// Reset the fast_single cache. Called after health checks and when
    /// clearing force-pinned selection.
    /// mihomo compat: matches URLTest.healthCheck() resetting fastSingle.
    pub fn reset_fast_single(&self) {
        self.fast_single.reset();
    }

    /// Trigger an immediate health check via the background loop.
    /// mihomo compat: urltest.go:101-104 — URLTest.healthCheck() brackets
    /// GroupBase.healthCheck() with `fastSingle.Reset()`. The trailing reset
    /// is ours too: health.rs calls `after_health_check()` once the triggered
    /// pass finishes, which is where the fresh results land.
    fn do_health_check(&self) {
        self.fast_single.reset();
        self.base.do_health_check();
    }
}

impl ProxyGroup for UrlTestGroup {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn group_type(&self) -> &str {
        "URLTest"
    }

    fn now(&self) -> String {
        self.fast()
    }

    fn all(&self) -> Vec<String> {
        self.base.all()
    }

    fn select(&self, name: &str) -> bool {
        // mihomo compat: URLTest supports force-pinning via Set/ForceSet.
        if self.base.contains(name) {
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

    fn fixed(&self) -> String {
        // mihomo compat: urltest.go:181 — `fixed` is the pinned name, kept
        // even while the pinned proxy is dead.
        self.force_selected.read().clone().unwrap_or_default()
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
        for name in self.base.proxy_names() {
            if let Some(handler) = proxies.get(name) {
                return Some(handler.clone());
            }
        }
        None
    }

    /// mihomo compat: GroupBase.onDialFailed() in groupbase.go — urltest.go
    /// passes `u.healthCheck` as the trigger, so the fastSingle reset runs.
    fn on_dial_failed(&self, proxy_type: &str, err: &str) {
        self.base
            .on_dial_failed(proxy_type, err, || self.do_health_check());
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

/// Parse the HTTP status code from a response status line ("HTTP/1.1 204 ...").
fn parse_status_line(buf: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(buf).ok()?;
    if !s.starts_with("HTTP/") {
        return None;
    }
    s.get(9..12)?.trim().parse().ok()
}

/// No-verify TLS client config for HTTPS health probes, built once.
static PROBE_TLS_CONFIG: std::sync::LazyLock<Arc<rustls::ClientConfig>> =
    std::sync::LazyLock::new(|| {
        let provider = rustls::crypto::ring::default_provider();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .expect("tls config")
                .dangerous()
                .with_custom_certificate_verifier(
                    Arc::new(crate::transport::tls::NoVerifier::new()),
                )
                .with_no_client_auth(),
        )
    });

/// Send an HTTP HEAD request, read the status line, and shut the stream down.
async fn head_status<S>(stream: &mut S, req: &str) -> anyhow::Result<Option<u16>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(req.as_bytes()).await?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await?;
    let status = parse_status_line(&buf[..n]);
    let _ = stream.shutdown().await;
    Ok(status)
}

/// Measure latency by connecting through a proxy and sending an HTTP HEAD request.
/// Returns the total elapsed time in milliseconds and the HTTP status code.
///
/// mihomo compat: matches adapter.go URLTest() which uses a 30s HTTP client timeout,
/// dials through the proxy, sends HEAD, reads the status line. The status code
/// is returned so callers can apply expected-status "satisfied" semantics.
/// The caller (run_health_check) wraps this with the configurable per-check
/// timeout (default 5000ms, healthcheck.go:202).
pub(crate) async fn measure_unified_delay(
    handler: &Arc<dyn OutboundHandler>,
    url: &str,
    dns: &DnsResolver,
) -> anyhow::Result<(u64, u16)> {
    // Parse URL to extract host and port
    let parsed: url::Url = url.parse()?;
    let host = parsed.host_str().unwrap_or("www.gstatic.com").to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };

    let is_https = parsed.scheme() == "https";
    let target = Address::domain(&host, port);
    let start = Instant::now();

    // Connect through the proxy
    let stream = handler.connect_stream(&target, dns).await?;

    // mihomo compat: adapter.go URLTest uses a real net/http client that
    // performs the TLS handshake for https:// test URLs. Sending a plaintext
    // HEAD to a :443 endpoint makes the TLS server reply with an alert, which
    // we would misread as "dead" and mark every node down. So for https we
    // must wrap the proxied stream in TLS before the HEAD.
    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: clash\r\nConnection: close\r\n\r\n"
    );
    let status = if is_https {
        let tls_connector = tokio_rustls::TlsConnector::from(PROBE_TLS_CONFIG.clone());
        let server_name =
            rustls::pki_types::ServerName::try_from(host.clone()).unwrap_or_else(|_| {
                rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap()
            });
        let mut tls_stream = tls_connector.connect(server_name, stream).await?;
        head_status(&mut tls_stream, &req).await?
    } else {
        let mut stream = stream;
        head_status(&mut stream, &req).await?
    };

    let status = status.ok_or_else(|| anyhow::anyhow!("invalid HTTP response"))?;
    Ok((start.elapsed().as_millis() as u64, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<ProxyStateStore> {
        Arc::new(ProxyStateStore::new())
    }

    fn make_hc(url: &str) -> HealthCheckOpts {
        HealthCheckOpts {
            url: url.to_string(),
            interval_secs: 300,
            max_failed_times: None,
            test_timeout: None,
            lazy: false,
            expected_status: None,
        }
    }

    #[test]
    fn defaults_are_correct() {
        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["a".to_string(), "b".to_string()],
            150,
            make_hc("http://test.example/204"),
            make_store(),
        );
        assert_eq!(group.name(), "auto");
        assert_eq!(group.group_type(), "URLTest");
        assert_eq!(group.base().interval(), Duration::from_secs(300));
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
    fn dead_pin_falls_through_to_fastest_but_is_kept() {
        // mihomo compat: urltest.go fast() — a dead pinned proxy is skipped
        // (fastest alive wins) but `selected` is NOT cleared, so it resumes
        // when the proxy comes back alive.
        let store = make_store();
        let url = "http://test.example/204";
        store.record_result("a", url, Some(100));
        store.record_result("b", url, Some(200));

        let group = UrlTestGroup::new(
            "auto".to_string(),
            vec!["a".to_string(), "b".to_string()],
            0,
            make_hc(url),
            store.clone(),
        );
        assert!(group.select("b"));
        assert_eq!(group.now(), "b");

        // "b" goes dead: fall through to fastest alive, pin kept.
        store.record_result("b", url, None);
        group.reset_fast_single();
        assert_eq!(group.now(), "a");
        assert_eq!(group.fixed(), "b");

        // "b" comes back alive: pin resumes.
        store.record_result("b", url, Some(300));
        group.reset_fast_single();
        assert_eq!(group.now(), "b");
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
            vec!["slow".to_string(), "fast".to_string(), "medium".to_string()],
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

        // Now "b" becomes slightly faster, but within tolerance.
        // In production, `record_result` is followed by `reset_fast_single()`
        // (via health.rs after_health_check) so the singleflight cache reflects
        // fresh state — replicate that here.
        store.record_result("a", url, Some(120));
        store.record_result("b", url, Some(110));
        group.reset_fast_single();

        // Should stick with "a" since 120 <= 110 + 50
        assert_eq!(group.now(), "a");

        // Now "b" becomes much faster, exceeding tolerance
        store.record_result("b", url, Some(50));
        group.reset_fast_single();

        // Should switch to "b" since 120 > 50 + 50
        assert_eq!(group.now(), "b");
    }

    /// Stress test: 1000 proxies hammering the state store with concurrent writes.
    ///
    /// Simulates a worst-case router scenario: many proxy groups with overlapping
    /// health checks all writing results simultaneously to the shared store.
    /// Verifies no data races, no panics, history stays bounded at MAX_HISTORY.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_state_store_1000_proxies() {
        let store = Arc::new(ProxyStateStore::new());
        let num_proxies = 1000;
        let writes_per_proxy = 100;
        let num_urls = 5; // each proxy tested against 5 URLs

        let mut handles = Vec::new();
        for i in 0..num_proxies {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..writes_per_proxy {
                    let name = format!("proxy-{i}");
                    let url_idx = j % num_urls;
                    let url = format!("http://test-{url_idx}/204");
                    if j % 7 == 0 {
                        // ~14% failure rate
                        store.record_result(&name, &url, None);
                    } else {
                        store.record_result(&name, &url, Some(((j % 500) + 50) as u16));
                    }
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Verify: every proxy has bounded history, no corruption
        for i in 0..num_proxies {
            let name = format!("proxy-{i}");
            let history = store.delay_history(&name);
            assert!(!history.is_empty(), "proxy-{i} should have history");
            assert!(
                history.len() <= 10,
                "proxy-{i} history {} > MAX_HISTORY",
                history.len()
            );

            // Verify extra (per-URL) histories exist
            let extras = store.extra_delay_histories(&name);
            assert!(
                !extras.is_empty(),
                "proxy-{i} should have extra URL histories"
            );
            for val in extras.values() {
                let h = val.get("history").and_then(|v| v.as_array());
                assert!(h.is_some(), "proxy-{i} extra should have history array");
                assert!(h.unwrap().len() <= 10, "proxy-{i} extra history unbounded");
            }
        }
    }

    /// Stress test: rapid alive/dead toggling under contention.
    ///
    /// 500 tasks flip proxy alive state rapidly while 500 others read it.
    /// Catches data races in the AtomicBool/DashMap interaction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_alive_toggle_contention() {
        let store = Arc::new(ProxyStateStore::new());
        let num_proxies = 200;
        let iterations = 500;

        let mut handles = Vec::new();

        // Writers: toggle alive state rapidly
        for i in 0..num_proxies {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let name = format!("proxy-{i}");
                let url = "http://test/204";
                for j in 0..iterations {
                    if j % 2 == 0 {
                        store.record_result(&name, url, Some(100));
                    } else {
                        store.record_result(&name, url, None);
                    }
                }
            }));
        }

        // Readers: check alive state concurrently with writes
        for i in 0..num_proxies {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let name = format!("proxy-{i}");
                let url = "http://test/204";
                for _ in 0..iterations {
                    // These should never panic regardless of concurrent writes
                    let _ = store.alive_for_url(&name, url);
                    let _ = store.last_delay_for_url(&name, url);
                    let _ = store.delay_history(&name);
                    tokio::task::yield_now().await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // If we got here without panic/deadlock, the test passes
    }
}
