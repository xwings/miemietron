use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

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

/// mihomo compat: adapter.UnifiedDelay is applied at startup and config reload.
static UNIFIED_DELAY: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_unified_delay(enabled: bool) {
    UNIFIED_DELAY.store(enabled, Ordering::Relaxed);
}

/// Shared URLTest path for controller requests and background health checks.
pub(crate) async fn measure_unified_delay(
    handler: &Arc<dyn OutboundHandler>,
    url: &str,
    dns: &DnsResolver,
) -> anyhow::Result<(u16, u16)> {
    measure_delay(handler, url, dns, UNIFIED_DELAY.load(Ordering::Relaxed)).await
}

async fn measure_delay(
    handler: &Arc<dyn OutboundHandler>,
    url: &str,
    dns: &DnsResolver,
    unified: bool,
) -> anyhow::Result<(u16, u16)> {
    let parsed: url::Url = url.parse()?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "unsupported URL scheme"
    );
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing URL host"))?;
    let port = parsed.port_or_known_default().unwrap();
    let target = Address::domain(host, port);
    let start = Instant::now();
    let stream = handler.connect_stream(&target, dns).await?;
    let stream: Box<dyn crate::proxy::ProxyStream> = if parsed.scheme() == "https" {
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        Box::new(
            tokio_rustls::TlsConnector::from(PROBE_TLS_CONFIG.clone())
                .connect(server_name, stream)
                .await?,
        )
    } else {
        stream
    };

    // A real HTTP connection consumes complete response headers and flushes
    // framed transports before reading. HEAD responses have no response body.
    let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, axum::body::Body>(
        hyper_util::rt::TokioIo::new(stream),
    )
    .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = || {
        http::Request::builder()
            .method(http::Method::HEAD)
            .uri(&parsed[url::Position::BeforePath..url::Position::AfterQuery])
            .header(
                http::header::HOST,
                &parsed[url::Position::BeforeHost..url::Position::AfterPort],
            )
            .body(axum::body::Body::empty())
    };
    let response = sender.send_request(request()?).await?;
    let mut status = response.status().as_u16();
    drop(response);
    let mut measured_from = start;
    if unified {
        // mihomo compat: adapter.go URLTest measures a second HEAD over the
        // established tunnel. If it fails, retain the first result and timer.
        let second = Instant::now();
        let result = async {
            sender.ready().await?;
            sender
                .send_request(request()?)
                .await
                .map_err(anyhow::Error::from)
        }
        .await;
        if let Ok(response) = result {
            status = response.status().as_u16();
            measured_from = second;
        }
    }
    let delay = measured_from.elapsed().as_millis() as u16;
    Ok((delay.max(1), status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn probes_reuse_the_tunnel_and_measure_the_configured_request() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

        struct ProbeOutbound(std::sync::Mutex<Option<DuplexStream>>);

        #[async_trait::async_trait]
        impl OutboundHandler for ProbeOutbound {
            fn name(&self) -> &str {
                "probe"
            }
            fn proto(&self) -> &str {
                "test"
            }
            fn supports_udp(&self) -> bool {
                false
            }
            async fn connect_stream(
                &self,
                target: &Address,
                _dns: &DnsResolver,
            ) -> anyhow::Result<Box<dyn crate::proxy::ProxyStream>> {
                assert_eq!(target, &Address::domain("probe.example", 8080));
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(Box::new(
                    self.0.lock().unwrap().take().expect("probe redialed"),
                ))
            }
        }

        let dns = DnsResolver::new(&crate::config::DnsConfig::default())
            .await
            .unwrap();
        for (unified, fail_second, expected_delay, expected_status) in [
            (false, false, 420, 204),
            (true, false, 60, 200),
            (true, true, 470, 204),
        ] {
            let (client, server) = tokio::io::duplex(4096);
            let handler: Arc<dyn OutboundHandler> =
                Arc::new(ProbeOutbound(std::sync::Mutex::new(Some(client))));
            let peer = tokio::spawn(async move {
                let mut stream = BufReader::new(server);
                for request in 0..if unified { 2 } else { 1 } {
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    assert_eq!(line, "HEAD /generate_204?check=1 HTTP/1.1\r\n");
                    let mut headers = String::new();
                    loop {
                        line.clear();
                        stream.read_line(&mut line).await.unwrap();
                        assert!(!line.is_empty(), "request headers truncated");
                        if line == "\r\n" {
                            break;
                        }
                        headers.push_str(&line.to_ascii_lowercase());
                    }
                    assert!(headers.contains("host: probe.example:8080\r\n"));
                    assert!(!headers.contains("connection: close"));
                    if request == 1 && fail_second {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(if request == 0 { 100 } else { 40 }))
                        .await;
                    stream
                        .write_all(if request == 0 {
                            b"HTTP/1.1 204 No Content\r\n"
                        } else {
                            b"HTTP/1.1 200 OK\r\n"
                        })
                        .await
                        .unwrap();
                    // Receiving a status line alone must not complete the probe.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    stream
                        .write_all(b"Content-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            });
            let (delay, status) = measure_delay(
                &handler,
                "http://probe.example:8080/generate_204?check=1",
                &dns,
                unified,
            )
            .await
            .unwrap();
            assert_eq!(status, expected_status);
            assert_eq!(
                delay, expected_delay,
                "unified={unified}, fail_second={fail_second}"
            );
            peer.await.unwrap();
        }
    }

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
