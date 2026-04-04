pub mod direct;
pub mod shadowsocks;
pub mod ssr;

#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "vless")]
pub mod vless;
#[cfg(feature = "vmess")]
pub mod vmess;

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::common::addr::Address;
use crate::config::proxy::{ProxyConfig, ProxyGroupConfig, ProxyProviderConfig};
use crate::dns::DnsResolver;
use crate::proxy_group::{
    FallbackGroup, LoadBalanceGroup, LoadBalanceStrategy, ProxyGroup, RelayGroup, SelectorGroup,
    UrlTestGroup,
};

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
    group_configs: Vec<ProxyGroupConfig>,
    live_groups: HashMap<String, Arc<dyn ProxyGroup>>,
    provider_configs: HashMap<String, ProxyProviderConfig>,
}

impl ProxyManager {
    pub async fn new(
        proxy_configs: &[ProxyConfig],
        group_configs: &[ProxyGroupConfig],
        providers: &HashMap<String, ProxyProviderConfig>,
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
            if let Some(handler) = Self::load_proxy_config(config) {
                proxies.insert(config.name.clone(), handler);
            }
        }

        // Load proxy providers and add their proxies.
        // Track which proxy names come from each provider for group expansion.
        let mut provider_proxy_names: HashMap<String, Vec<String>> = HashMap::new();
        for (prov_name, prov_config) in providers {
            match Self::load_proxy_provider(prov_name, prov_config).await {
                Ok(provider_proxies) => {
                    let mut names = Vec::new();
                    for pc in &provider_proxies {
                        names.push(pc.name.clone());
                        if let Some(handler) = Self::load_proxy_config(pc) {
                            proxies.insert(pc.name.clone(), handler);
                        }
                    }
                    info!(
                        "Proxy provider '{}' loaded {} proxies",
                        prov_name,
                        names.len()
                    );
                    provider_proxy_names.insert(prov_name.clone(), names);
                }
                Err(e) => {
                    tracing::warn!("Failed to load proxy provider '{}': {}", prov_name, e);
                    provider_proxy_names.insert(prov_name.clone(), Vec::new());
                }
            }
        }

        // Build live proxy group instances from config.
        // Expand `use` (provider references) into the proxies list.
        let mut live_groups: HashMap<String, Arc<dyn ProxyGroup>> = HashMap::new();
        for gc in group_configs {
            let mut all_proxies = gc.proxies.clone();

            // Expand `use` provider references
            for prov_name in &gc.use_providers {
                if let Some(prov_proxies) = provider_proxy_names.get(prov_name) {
                    all_proxies.extend(prov_proxies.iter().cloned());
                } else {
                    tracing::warn!(
                        "Proxy group '{}' references unknown provider '{}'",
                        gc.name,
                        prov_name
                    );
                }
            }

            // Handle include-all-providers flag
            if gc.include_all_providers.unwrap_or(false) {
                for prov_proxies in provider_proxy_names.values() {
                    for name in prov_proxies {
                        if !all_proxies.contains(name) {
                            all_proxies.push(name.clone());
                        }
                    }
                }
            }

            // Handle include-all-proxies flag
            if gc.include_all_proxies.unwrap_or(false) {
                for config in proxy_configs {
                    if !all_proxies.contains(&config.name) {
                        all_proxies.push(config.name.clone());
                    }
                }
            }

            // Handle include-all flag (includes both proxies and providers)
            if gc.include_all.unwrap_or(false) {
                for config in proxy_configs {
                    if !all_proxies.contains(&config.name) {
                        all_proxies.push(config.name.clone());
                    }
                }
                for prov_proxies in provider_proxy_names.values() {
                    for name in prov_proxies {
                        if !all_proxies.contains(name) {
                            all_proxies.push(name.clone());
                        }
                    }
                }
            }

            let group: Arc<dyn ProxyGroup> = match gc.group_type.as_str() {
                "select" => Arc::new(SelectorGroup::new(gc.name.clone(), all_proxies)),
                "url-test" => Arc::new(UrlTestGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    gc.url
                        .clone()
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                    gc.interval.unwrap_or(300),
                    gc.tolerance.unwrap_or(150),
                )),
                "fallback" => Arc::new(FallbackGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    gc.url
                        .clone()
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                    gc.interval.unwrap_or(300),
                )),
                "load-balance" => Arc::new(LoadBalanceGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    LoadBalanceStrategy::from_str(
                        gc.strategy.as_deref().unwrap_or("consistent-hashing"),
                    ),
                )),
                "relay" => Arc::new(RelayGroup::new(gc.name.clone(), all_proxies)),
                other => {
                    info!(
                        "Unknown proxy group type '{}' for '{}', treating as selector",
                        other, gc.name
                    );
                    Arc::new(SelectorGroup::new(gc.name.clone(), all_proxies))
                }
            };
            info!(
                "Created proxy group '{}' (type: {})",
                gc.name, gc.group_type
            );
            live_groups.insert(gc.name.clone(), group);
        }

        Ok(Self {
            proxies,
            group_configs: group_configs.to_vec(),
            live_groups,
            provider_configs: providers.clone(),
        })
    }

    /// Load a single proxy from config, returning an OutboundHandler or None.
    fn load_proxy_config(config: &ProxyConfig) -> Option<Arc<dyn OutboundHandler>> {
        match config.proxy_type.as_str() {
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
            #[cfg(feature = "vmess")]
            "vmess" => {
                info!("Loading VMess proxy: {}", config.name);
                match vmess::VmessOutbound::new(config) {
                    Ok(handler) => Some(Arc::new(handler)),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load VMess proxy '{}': {}, using placeholder",
                            config.name,
                            e
                        );
                        Some(Arc::new(direct::PlaceholderOutbound::new(
                            config.name.clone(),
                            "vmess",
                        )))
                    }
                }
            }
            "ssr" => {
                info!("Loading SSR proxy: {}", config.name);
                match ssr::SsrOutbound::from_config(config) {
                    Ok(handler) => Some(Arc::new(handler)),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load SSR proxy '{}': {}, using placeholder",
                            config.name,
                            e
                        );
                        Some(Arc::new(direct::PlaceholderOutbound::new(
                            config.name.clone(),
                            "ssr",
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
        }
    }

    /// Load proxies from a proxy provider (file or HTTP).
    async fn load_proxy_provider(
        name: &str,
        config: &ProxyProviderConfig,
    ) -> Result<Vec<ProxyConfig>> {
        let content = match config.provider_type.as_str() {
            "file" => {
                let path = config
                    .path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("file provider '{name}' has no path"))?;
                tokio::fs::read_to_string(path).await.map_err(|e| {
                    anyhow::anyhow!("failed to read proxy provider file '{path}': {e}")
                })?
            }
            "http" => {
                // Try local cache first, then fetch from URL
                if let Some(ref path) = config.path {
                    let pb = std::path::PathBuf::from(path);
                    if pb.exists() {
                        tokio::fs::read_to_string(&pb).await.unwrap_or_default()
                    } else {
                        let url = config
                            .url
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("HTTP provider '{name}' has no URL"))?;
                        let resp = reqwest::get(url).await?;
                        let text = resp.text().await?;
                        // Cache to disk
                        if let Some(parent) = pb.parent() {
                            tokio::fs::create_dir_all(parent).await.ok();
                        }
                        tokio::fs::write(&pb, &text).await.ok();
                        text
                    }
                } else {
                    let url = config
                        .url
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("HTTP provider '{name}' has no URL"))?;
                    reqwest::get(url).await?.text().await?
                }
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unknown proxy provider type '{other}' for '{name}'"
                ));
            }
        };

        // Parse YAML: the content has a `proxies:` list in the same format
        // as the main config.
        #[derive(serde::Deserialize)]
        struct ProviderYaml {
            #[serde(default)]
            proxies: Vec<ProxyConfig>,
        }

        let parsed: ProviderYaml = serde_yaml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse proxy provider '{name}' YAML: {e}"))?;

        Ok(parsed.proxies)
    }

    /// Get an outbound handler by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.proxies.get(name).cloned()
    }

    /// Get proxy for the given action target name.
    /// Resolves proxy groups to their selected/active proxy.
    pub fn resolve(&self, target: &str) -> Option<Arc<dyn OutboundHandler>> {
        // First check if target is a direct proxy
        if let Some(proxy) = self.proxies.get(target) {
            return Some(proxy.clone());
        }

        // Check live proxy groups
        if let Some(group) = self.live_groups.get(target) {
            // The group's selected proxy might itself be another group name,
            // so resolve recursively (with a depth limit to avoid loops).
            let selected_name = group.now();
            if let Some(proxy) = self.proxies.get(&selected_name) {
                return Some(proxy.clone());
            }
            // The selected proxy may be another group -- resolve one level deep
            if let Some(inner_group) = self.live_groups.get(&selected_name) {
                return inner_group.get_proxy(&self.proxies);
            }
            // Fall back to group's own resolution logic
            return group.get_proxy(&self.proxies);
        }

        None
    }

    /// Select a proxy within a named group. Returns true on success.
    pub fn select_proxy(&self, group_name: &str, proxy_name: &str) -> bool {
        if let Some(group) = self.live_groups.get(group_name) {
            group.select(proxy_name)
        } else {
            false
        }
    }

    /// Get a live proxy group by name.
    pub fn get_group(&self, name: &str) -> Option<Arc<dyn ProxyGroup>> {
        self.live_groups.get(name).cloned()
    }

    /// Get all proxy names in a group.
    pub fn group_proxy_names(&self, group_name: &str) -> Option<Vec<String>> {
        self.live_groups.get(group_name).map(|g| g.all())
    }

    /// Get the internal proxies map (for health checks / delay tests).
    pub fn proxies_map(&self) -> &HashMap<String, Arc<dyn OutboundHandler>> {
        &self.proxies
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
        &self.group_configs
    }

    /// List all live proxy groups (for API — includes runtime state).
    pub fn list_live_groups(&self) -> &HashMap<String, Arc<dyn ProxyGroup>> {
        &self.live_groups
    }

    /// Apply saved proxy group selections (from persistent store).
    /// Silently skips groups or proxies that no longer exist.
    pub fn apply_saved_selections(&self, selections: &std::collections::HashMap<String, String>) {
        for (group_name, proxy_name) in selections {
            if let Some(group) = self.live_groups.get(group_name) {
                if group.select(proxy_name) {
                    tracing::debug!(
                        "Restored saved selection: group '{}' -> '{}'",
                        group_name,
                        proxy_name
                    );
                }
            }
        }
    }

    /// Get all current proxy group selections as a map (for persistence).
    pub fn get_all_selections(&self) -> std::collections::HashMap<String, String> {
        self.live_groups
            .iter()
            .map(|(name, group)| (name.clone(), group.now()))
            .collect()
    }

    /// Get a proxy provider config by name.
    pub fn get_provider_config(&self, name: &str) -> Option<&ProxyProviderConfig> {
        self.provider_configs.get(name)
    }

    /// List all proxy provider configs (for API).
    pub fn list_provider_configs(&self) -> &HashMap<String, ProxyProviderConfig> {
        &self.provider_configs
    }

    /// Update a proxy provider by fetching its URL and reloading proxies.
    /// Returns Ok(()) if the provider was found and the update was attempted.
    pub async fn update_provider(&self, name: &str) -> Result<()> {
        let config = self
            .provider_configs
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("provider '{name}' not found"))?;

        let url = config
            .url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("provider '{name}' has no URL configured"))?;

        info!("Updating proxy provider '{}' from {}", name, url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = client.get(url).send().await?;
        let body = resp.text().await?;

        // Save to path if configured
        if let Some(ref path) = config.path {
            let path = std::path::Path::new(path);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(path, &body)?;
            info!("Proxy provider '{}' saved to {}", name, path.display());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub udp: bool,
}
