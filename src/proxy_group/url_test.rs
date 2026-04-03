use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::proxy::OutboundHandler;

use super::ProxyGroup;

/// Auto-select the proxy with the lowest measured latency.
///
/// Health checks run concurrently against a configurable URL. Results are
/// stored in a `tokio::sync::RwLock<HashMap<String, u64>>` mapping proxy
/// names to their round-trip delay in milliseconds. `get_proxy` returns the
/// proxy with the smallest delay value.
pub struct UrlTestGroup {
    group_name: String,
    proxy_names: Vec<String>,
    test_url: String,
    interval: Duration,
    tolerance: u32,
    /// proxy_name -> delay_ms (0 or absent means unknown/dead)
    delays: Arc<RwLock<HashMap<String, u64>>>,
}

impl UrlTestGroup {
    pub fn new(
        name: String,
        proxies: Vec<String>,
        url: String,
        interval_secs: u64,
        tolerance: u32,
    ) -> Self {
        Self {
            group_name: name,
            proxy_names: proxies,
            test_url: url,
            interval: Duration::from_secs(interval_secs),
            tolerance,
            delays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The configured health check interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The configured test URL.
    pub fn test_url(&self) -> &str {
        &self.test_url
    }

    /// Run a health check against all proxies concurrently.
    ///
    /// Each proxy is tested by issuing an HTTP HEAD request through `reqwest`
    /// to `self.test_url` and measuring the elapsed time. Results are written
    /// back into `self.delays`.
    pub async fn health_check(&self, proxies: &HashMap<String, Arc<dyn OutboundHandler>>) {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "url-test {}: failed to build HTTP client: {}",
                    self.group_name, e
                );
                return;
            }
        };

        let mut handles = Vec::new();

        for name in &self.proxy_names {
            if !proxies.contains_key(name) {
                continue;
            }
            let name = name.clone();
            let url = self.test_url.clone();
            let client = client.clone();
            let delays = self.delays.clone();

            let handle = tokio::spawn(async move {
                let start = Instant::now();
                let result = client.head(&url).send().await;
                let elapsed = start.elapsed().as_millis() as u64;

                match result {
                    Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                        debug!("url-test {}: {}ms", name, elapsed);
                        delays.write().await.insert(name, elapsed);
                    }
                    Ok(resp) => {
                        warn!("url-test {}: HTTP {}", name, resp.status());
                        delays.write().await.remove(&name);
                    }
                    Err(e) => {
                        warn!("url-test {}: {}", name, e);
                        delays.write().await.remove(&name);
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
    pub async fn get_delays(&self) -> HashMap<String, u64> {
        self.delays.read().await.clone()
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
        // Return the proxy with the lowest delay. This blocks on the async
        // lock via try_read; if contended we fall back to the first proxy.
        if let Ok(delays) = self.delays.try_read() {
            if let Some((name, _)) = delays
                .iter()
                .filter(|(n, _)| self.proxy_names.contains(n))
                .min_by_key(|(_, &d)| d)
            {
                return name.clone();
            }
        }
        self.proxy_names.first().cloned().unwrap_or_default()
    }

    fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    fn select(&self, _name: &str) -> bool {
        // URLTest does not support manual selection.
        false
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        // Pick the proxy with the lowest latency from the most recent health
        // check. If no results yet, fall through to the first proxy.
        if let Ok(delays) = self.delays.try_read() {
            let best = delays
                .iter()
                .filter(|(n, _)| self.proxy_names.contains(n))
                .min_by_key(|(_, &d)| d);

            if let Some((name, _)) = best {
                if let Some(handler) = proxies.get(name) {
                    return Some(handler.clone());
                }
            }
        }

        // Fallback: first available proxy in list order.
        for name in &self.proxy_names {
            if let Some(handler) = proxies.get(name) {
                return Some(handler.clone());
            }
        }
        None
    }
}
