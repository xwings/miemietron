use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::proxy::OutboundHandler;

use super::ProxyGroup;

/// Fallback group: pick the first proxy that is alive.
///
/// Like UrlTest, it periodically health-checks all proxies. Unlike UrlTest,
/// it does **not** pick the lowest-latency proxy. Instead it walks the proxy
/// list in order and returns the first one whose last health check succeeded.
pub struct FallbackGroup {
    group_name: String,
    proxy_names: Vec<String>,
    test_url: String,
    interval: Duration,
    /// proxy_name -> delay_ms. Absent means the proxy is dead / untested.
    alive: Arc<RwLock<HashMap<String, u64>>>,
}

impl FallbackGroup {
    pub fn new(name: String, proxies: Vec<String>, url: String, interval_secs: u64) -> Self {
        Self {
            group_name: name,
            proxy_names: proxies,
            test_url: url,
            interval: Duration::from_secs(interval_secs),
            alive: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn test_url(&self) -> &str {
        &self.test_url
    }

    /// Run a health check against all proxies concurrently.
    pub async fn health_check(&self, proxies: &HashMap<String, Arc<dyn OutboundHandler>>) {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "fallback {}: failed to build HTTP client: {}",
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
            let alive = self.alive.clone();

            let handle = tokio::spawn(async move {
                let start = Instant::now();
                let result = client.head(&url).send().await;
                let elapsed = start.elapsed().as_millis() as u64;

                match result {
                    Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                        debug!("fallback {}: alive ({}ms)", name, elapsed);
                        alive.write().await.insert(name, elapsed);
                    }
                    Ok(resp) => {
                        warn!("fallback {}: HTTP {}", name, resp.status());
                        alive.write().await.remove(&name);
                    }
                    Err(e) => {
                        warn!("fallback {}: {}", name, e);
                        alive.write().await.remove(&name);
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }
    }

    pub async fn get_alive(&self) -> HashMap<String, u64> {
        self.alive.read().await.clone()
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
        if let Ok(alive) = self.alive.try_read() {
            for name in &self.proxy_names {
                if alive.contains_key(name) {
                    return name.clone();
                }
            }
        }
        // If nothing is alive, return the first proxy (optimistic).
        self.proxy_names.first().cloned().unwrap_or_default()
    }

    fn all(&self) -> Vec<String> {
        self.proxy_names.clone()
    }

    fn select(&self, _name: &str) -> bool {
        false
    }

    fn get_proxy(
        &self,
        proxies: &HashMap<String, Arc<dyn OutboundHandler>>,
    ) -> Option<Arc<dyn OutboundHandler>> {
        // Walk the list in config order and return the first alive proxy.
        if let Ok(alive) = self.alive.try_read() {
            for name in &self.proxy_names {
                if alive.contains_key(name) {
                    if let Some(handler) = proxies.get(name) {
                        return Some(handler.clone());
                    }
                }
            }
        }

        // Fallback: first in list.
        for name in &self.proxy_names {
            if let Some(handler) = proxies.get(name) {
                return Some(handler.clone());
            }
        }
        None
    }
}
