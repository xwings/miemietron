pub mod direct;
pub mod shadowsocks;

#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "vless")]
pub mod vless;

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::common::addr::Address;
use crate::config::proxy::{ProxyConfig, ProxyGroupConfig, ProxyProviderConfig};
use crate::dns::DnsResolver;

/// Bidirectional async byte stream.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

/// Outbound handler trait - all proxy protocols implement this.
#[async_trait]
pub trait OutboundHandler: Send + Sync {
    fn name(&self) -> &str;
    fn proto(&self) -> &str;
    fn supports_udp(&self) -> bool;

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>>;
}

/// Manages all configured proxies and provides lookup.
pub struct ProxyManager {
    proxies: HashMap<String, Arc<dyn OutboundHandler>>,
    groups: Vec<ProxyGroupConfig>,
}

impl ProxyManager {
    pub async fn new(
        proxy_configs: &[ProxyConfig],
        group_configs: &[ProxyGroupConfig],
        _providers: &HashMap<String, ProxyProviderConfig>,
    ) -> Result<Self> {
        let mut proxies: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        // Built-in proxies
        proxies.insert("DIRECT".to_string(), Arc::new(direct::DirectOutbound));
        proxies.insert("REJECT".to_string(), Arc::new(direct::RejectOutbound));
        proxies.insert(
            "REJECT-DROP".to_string(),
            Arc::new(direct::RejectDropOutbound),
        );

        // Parse configured proxies
        for config in proxy_configs {
            let handler: Option<Arc<dyn OutboundHandler>> = match config.proxy_type.as_str() {
                "ss" => {
                    info!("Loading SS proxy: {}", config.name);
                    match shadowsocks::ShadowsocksOutbound::from_config(config) {
                        Ok(handler) => Some(Arc::new(handler)),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load SS proxy '{}': {}, using placeholder",
                                config.name,
                                e
                            );
                            Some(Arc::new(direct::PlaceholderOutbound::new(
                                config.name.clone(),
                                "ss",
                            )))
                        }
                    }
                }
                #[cfg(feature = "vless")]
                "vless" => {
                    info!("Loading VLESS proxy: {}", config.name);
                    match vless::VlessOutbound::new(config) {
                        Ok(handler) => Some(Arc::new(handler)),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load VLESS proxy '{}': {}, using placeholder",
                                config.name,
                                e
                            );
                            Some(Arc::new(direct::PlaceholderOutbound::new(
                                config.name.clone(),
                                "vless",
                            )))
                        }
                    }
                }
                #[cfg(feature = "trojan")]
                "trojan" => {
                    info!("Loading Trojan proxy: {}", config.name);
                    match trojan::TrojanOutbound::new(config) {
                        Ok(handler) => Some(Arc::new(handler)),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load Trojan proxy '{}': {}, using placeholder",
                                config.name,
                                e
                            );
                            Some(Arc::new(direct::PlaceholderOutbound::new(
                                config.name.clone(),
                                "trojan",
                            )))
                        }
                    }
                }
                other => {
                    info!(
                        "Skipping unsupported proxy type: {} ({})",
                        other, config.name
                    );
                    None
                }
            };

            if let Some(handler) = handler {
                proxies.insert(config.name.clone(), handler);
            }
        }

        Ok(Self {
            proxies,
            groups: group_configs.to_vec(),
        })
    }

    /// Get an outbound handler by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.proxies.get(name).cloned()
    }

    /// Get proxy for the given action target name.
    /// Resolves proxy groups to their selected proxy.
    pub fn resolve(&self, target: &str) -> Option<Arc<dyn OutboundHandler>> {
        // First check if target is a direct proxy
        if let Some(proxy) = self.proxies.get(target) {
            return Some(proxy.clone());
        }

        // Check proxy groups
        for group in &self.groups {
            if group.name == target {
                // For now, use first proxy in the group
                if let Some(first) = group.proxies.first() {
                    return self.proxies.get(first).cloned();
                }
            }
        }

        None
    }

    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    /// List all proxy names and their types (for API).
    pub fn list_proxies(&self) -> Vec<ProxyInfo> {
        self.proxies
            .iter()
            .map(|(name, handler)| ProxyInfo {
                name: name.clone(),
                proxy_type: handler.proto().to_string(),
                udp: handler.supports_udp(),
            })
            .collect()
    }

    /// List all proxy group configs (for API).
    pub fn list_groups(&self) -> &[ProxyGroupConfig] {
        &self.groups
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub udp: bool,
}
