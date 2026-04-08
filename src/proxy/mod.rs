pub mod direct;
pub mod http;
pub mod shadowsocks;
pub mod snell;
pub mod socks5;
pub mod ssr;

#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "vless")]
pub mod vless;
#[cfg(feature = "vmess")]
pub mod vmess;

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::common::addr::Address;
use crate::config::proxy::{ProxyConfig, ProxyGroupConfig, ProxyProviderConfig};
use crate::dns::DnsResolver;
use crate::proxy_group::{
    FallbackGroup, LoadBalanceGroup, LoadBalanceStrategy, ProxyGroup, SelectorGroup, UrlTestGroup,
};

/// Bidirectional async byte stream.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

/// A UDP-capable outbound connection.
/// Analogous to mihomo's C.PacketConn / Go's net.PacketConn.
#[async_trait]
pub trait OutboundPacketConn: Send + Sync {
    /// Send `data` to `target` through this connection.
    async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize>;

    /// Receive a datagram. Returns (bytes_read, source_address).
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)>;

    /// Close the connection, releasing resources.
    async fn close(&self) -> Result<()>;
}

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

    /// Create a UDP-capable outbound connection for datagram relay.
    /// Returns Err by default — only protocols that support UDP override this.
    /// Analogous to mihomo's ListenPacketContext.
    async fn connect_datagram(
        &self,
        _target: &Address,
        _dns: Arc<DnsResolver>,
    ) -> Result<Box<dyn OutboundPacketConn>> {
        Err(anyhow::anyhow!(
            "{} ({}) does not support UDP relay",
            self.name(),
            self.proto()
        ))
    }
}

/// Subscription info parsed from proxy provider HTTP headers.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SubscriptionInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire: u64,
}

/// Manages all configured proxies and provides lookup.
pub struct ProxyManager {
    proxies: HashMap<String, Arc<dyn OutboundHandler>>,
    group_configs: Vec<ProxyGroupConfig>,
    live_groups: HashMap<String, Arc<dyn ProxyGroup>>,
    provider_configs: HashMap<String, ProxyProviderConfig>,
    subscription_info: HashMap<String, SubscriptionInfo>,
    /// Maps proxy name -> dialer proxy name (for proxy chaining)
    #[allow(dead_code)]
    dialer_proxy_map: HashMap<String, String>,
    /// Centralized per-proxy state store shared with all groups.
    state_store: Arc<crate::proxy_group::proxy_state::ProxyStateStore>,
}

impl ProxyManager {
    pub async fn new(
        proxy_configs: &[ProxyConfig],
        group_configs: &[ProxyGroupConfig],
        providers: &HashMap<String, ProxyProviderConfig>,
        global_routing_mark: Option<u32>,
        global_tcp_concurrent: bool,
        keep_alive_idle: u64,
        keep_alive_interval: u64,
        disable_keep_alive: bool,
    ) -> Result<Self> {
        let state_store = Arc::new(crate::proxy_group::proxy_state::ProxyStateStore::new());
        Self::with_state_store(
            proxy_configs,
            group_configs,
            providers,
            global_routing_mark,
            global_tcp_concurrent,
            state_store,
            keep_alive_idle,
            keep_alive_interval,
            disable_keep_alive,
        )
        .await
    }

    pub async fn with_state_store(
        proxy_configs: &[ProxyConfig],
        group_configs: &[ProxyGroupConfig],
        providers: &HashMap<String, ProxyProviderConfig>,
        global_routing_mark: Option<u32>,
        global_tcp_concurrent: bool,
        state_store: Arc<crate::proxy_group::proxy_state::ProxyStateStore>,
        keep_alive_idle: u64,
        keep_alive_interval: u64,
        disable_keep_alive: bool,
    ) -> Result<Self> {
        let mut proxies: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        // mihomo compat: DefaultRoutingMark starts at 0 in mihomo (dialer/options.go:14).
        // When no routing-mark is configured, mihomo does NOT set SO_MARK on sockets.
        // It relies on GID 65534 (set by OpenClash via procd) for firewall bypass.
        // Only set SO_MARK when the config explicitly specifies routing-mark.
        let global_routing_mark = global_routing_mark;

        // Built-in proxies — DIRECT gets the global routing mark for SO_MARK
        proxies.insert(
            "DIRECT".to_string(),
            Arc::new(direct::DirectOutbound::new(global_routing_mark)),
        );
        proxies.insert("REJECT".to_string(), Arc::new(direct::RejectOutbound));
        proxies.insert(
            "REJECT-DROP".to_string(),
            Arc::new(direct::RejectDropOutbound),
        );

        // Parse configured proxies, applying global settings as defaults
        let mut dialer_proxy_map: HashMap<String, String> = HashMap::new();
        for config in proxy_configs {
            let mut cfg = config.clone();
            if cfg.routing_mark.is_none() {
                cfg.routing_mark = global_routing_mark;
            }
            if cfg.tcp_concurrent.is_none() && global_tcp_concurrent {
                cfg.tcp_concurrent = Some(true);
            }
            // mihomo compat: inject global keepalive settings
            if cfg.keep_alive_idle.is_none() {
                cfg.keep_alive_idle = Some(keep_alive_idle);
            }
            if cfg.keep_alive_interval.is_none() {
                cfg.keep_alive_interval = Some(keep_alive_interval);
            }
            if cfg.disable_keep_alive.is_none() {
                cfg.disable_keep_alive = Some(disable_keep_alive);
            }
            // Track dialer-proxy relationships
            if let Some(ref dialer) = cfg.dialer_proxy {
                dialer_proxy_map.insert(cfg.name.clone(), dialer.clone());
            }
            if let Some(handler) = Self::load_proxy_config(&cfg) {
                proxies.insert(cfg.name.clone(), handler);
            }
        }

        // Load proxy providers and add their proxies.
        // Track which proxy names come from each provider for group expansion.
        let mut provider_proxy_names: HashMap<String, Vec<String>> = HashMap::new();
        let mut subscription_info: HashMap<String, SubscriptionInfo> = HashMap::new();
        for (prov_name, prov_config) in providers {
            match Self::load_proxy_provider(prov_name, prov_config).await {
                Ok((provider_proxies, sub_info)) => {
                    if let Some(info) = sub_info {
                        subscription_info.insert(prov_name.clone(), info);
                    }
                    let mut names = Vec::new();
                    for pc in &provider_proxies {
                        names.push(pc.name.clone());
                        let mut cfg = pc.clone();
                        if cfg.routing_mark.is_none() {
                            cfg.routing_mark = global_routing_mark;
                        }
                        if cfg.tcp_concurrent.is_none() && global_tcp_concurrent {
                            cfg.tcp_concurrent = Some(true);
                        }
                        if let Some(handler) = Self::load_proxy_config(&cfg) {
                            proxies.insert(cfg.name.clone(), handler);
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
        // mihomo compat: filter regex only applies to non-Compatible providers
        // (i.e., subscription/file providers from `use`), NOT to directly listed proxies.
        // exclude-filter and exclude-type apply to all proxies regardless of source.
        let mut live_groups: HashMap<String, Arc<dyn ProxyGroup>> = HashMap::new();
        for gc in group_configs {
            // Parse filter regexes (backtick-separated patterns)
            // mihomo compat: uses regexp2 (RE2-compatible), Rust regex crate is compatible
            let filter_regs: Vec<Regex> = gc
                .filter
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.split('`')
                        .filter_map(|pat| match Regex::new(pat) {
                            Ok(re) => Some(re),
                            Err(e) => {
                                tracing::warn!(
                                    "Proxy group '{}': invalid filter regex '{}': {}",
                                    gc.name,
                                    pat,
                                    e
                                );
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let exclude_filter_regs: Vec<Regex> = gc
                .exclude_filter
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.split('`')
                        .filter_map(|pat| match Regex::new(pat) {
                            Ok(re) => Some(re),
                            Err(e) => {
                                tracing::warn!(
                                    "Proxy group '{}': invalid exclude-filter regex '{}': {}",
                                    gc.name,
                                    pat,
                                    e
                                );
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let exclude_type_array: Vec<String> = gc
                .exclude_type
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| s.split('|').map(|t| t.trim().to_string()).collect())
                .unwrap_or_default();

            // Compatible proxies: directly listed in the group config (no filter applied)
            let mut compatible_proxies = gc.proxies.clone();
            let mut compatible_set: std::collections::HashSet<String> =
                compatible_proxies.iter().cloned().collect();

            // mihomo compat: include-all implies include-all-providers + include-all-proxies
            let include_all_providers =
                gc.include_all_providers.unwrap_or(false) || gc.include_all.unwrap_or(false);
            let include_all_proxies =
                gc.include_all_proxies.unwrap_or(false) || gc.include_all.unwrap_or(false);

            // Handle include-all-proxies: mihomo pre-filters with filter regex
            // before adding to the compatible list (parser.go lines 84-99)
            if include_all_proxies {
                if !filter_regs.is_empty() {
                    for pc in proxy_configs {
                        if compatible_set.contains(&pc.name) {
                            continue;
                        }
                        for filter_reg in &filter_regs {
                            if filter_reg.is_match(&pc.name) {
                                compatible_set.insert(pc.name.clone());
                                compatible_proxies.push(pc.name.clone());
                                break;
                            }
                        }
                    }
                } else {
                    for pc in proxy_configs {
                        if compatible_set.insert(pc.name.clone()) {
                            compatible_proxies.push(pc.name.clone());
                        }
                    }
                }
            }

            // Provider proxies: from `use` and include-all-providers (filter applied)
            let mut provider_proxies: Vec<String> = Vec::new();
            let mut provider_set: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            // Expand `use` provider references
            for prov_name in &gc.use_providers {
                if let Some(prov_proxies) = provider_proxy_names.get(prov_name) {
                    for name in prov_proxies {
                        if provider_set.insert(name.clone()) {
                            provider_proxies.push(name.clone());
                        }
                    }
                } else {
                    tracing::warn!(
                        "Proxy group '{}' references unknown provider '{}'",
                        gc.name,
                        prov_name
                    );
                }
            }

            // Handle include-all-providers flag
            if include_all_providers {
                for prov_proxies in provider_proxy_names.values() {
                    for name in prov_proxies {
                        if provider_set.insert(name.clone()) {
                            provider_proxies.push(name.clone());
                        }
                    }
                }
            }

            // Apply filter regex to provider proxies only (not compatible)
            // mihomo compat (groupbase.go lines 135-161): filter acts as include-only;
            // multiple backtick-separated patterns are OR'd. Proxies are ordered by
            // filter pattern appearance (deduped).
            if !filter_regs.is_empty() {
                let mut filtered: Vec<String> = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for filter_reg in &filter_regs {
                    for name in &provider_proxies {
                        if filter_reg.is_match(name) && seen.insert(name.clone()) {
                            filtered.push(name.clone());
                        }
                    }
                }
                provider_proxies = filtered;
            }

            // Combine: compatible proxies first, then (filtered) provider proxies
            // mihomo compat: Compatible provider is prepended to the providers list
            let mut all_proxies = compatible_proxies;
            all_proxies.extend(provider_proxies);

            // Apply exclude-filter regex (remove any proxy matching ANY pattern)
            // mihomo compat (groupbase.go lines 190-203): applies to ALL proxies
            if !exclude_filter_regs.is_empty() {
                all_proxies
                    .retain(|name| !exclude_filter_regs.iter().any(|re| re.is_match(name)));
            }

            // Apply exclude-type (remove proxies of specified types, case-insensitive)
            // mihomo compat (groupbase.go lines 205-218): applies to ALL proxies
            if !exclude_type_array.is_empty() {
                all_proxies.retain(|name| {
                    if let Some(handler) = proxies.get(name) {
                        !exclude_type_array
                            .iter()
                            .any(|t| handler.proto().eq_ignore_ascii_case(t))
                    } else {
                        true // keep unknown proxies (e.g., other group names)
                    }
                });
            }

            // mihomo compat: if no proxies remain after filtering, fall back to COMPATIBLE
            if all_proxies.is_empty() {
                tracing::warn!(
                    "Proxy group '{}' has no proxies after filtering",
                    gc.name
                );
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
                    state_store.clone(),
                    gc.max_failed_times,
                    gc.timeout,
                    gc.lazy.unwrap_or(false),
                )),
                "fallback" => Arc::new(FallbackGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    gc.url
                        .clone()
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                    gc.interval.unwrap_or(300),
                    state_store.clone(),
                    gc.max_failed_times,
                    gc.timeout,
                    gc.lazy.unwrap_or(false),
                )),
                "load-balance" => Arc::new(LoadBalanceGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    LoadBalanceStrategy::from_str(
                        gc.strategy.as_deref().unwrap_or("consistent-hashing"),
                    ),
                )),
                "relay" => {
                    // mihomo compat: relay groups removed in Meta branch
                    tracing::error!(
                        "The group [{}] with relay type was removed, please using dialer-proxy instead",
                        gc.name
                    );
                    continue;
                }
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
            subscription_info,
            dialer_proxy_map,
            state_store,
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
                            config.routing_mark,
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
                            config.routing_mark,
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
                            config.routing_mark,
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
                            config.routing_mark,
                        )))
                    }
                }
            }
            "http" => {
                info!("Loading HTTP proxy: {}", config.name);
                match http::HttpOutbound::from_config(config) {
                    Ok(handler) => Some(Arc::new(handler)),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load HTTP proxy '{}': {}, using placeholder",
                            config.name,
                            e
                        );
                        Some(Arc::new(direct::PlaceholderOutbound::new(
                            config.name.clone(),
                            "http",
                            config.routing_mark,
                        )))
                    }
                }
            }
            "socks5" => {
                info!("Loading SOCKS5 proxy: {}", config.name);
                match socks5::Socks5Outbound::from_config(config) {
                    Ok(handler) => Some(Arc::new(handler)),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load SOCKS5 proxy '{}': {}, using placeholder",
                            config.name,
                            e
                        );
                        Some(Arc::new(direct::PlaceholderOutbound::new(
                            config.name.clone(),
                            "socks5",
                            config.routing_mark,
                        )))
                    }
                }
            }
            "snell" => {
                info!("Loading Snell proxy: {}", config.name);
                match snell::SnellOutbound::from_config(config) {
                    Ok(handler) => Some(Arc::new(handler)),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load Snell proxy '{}': {}, using placeholder",
                            config.name,
                            e
                        );
                        Some(Arc::new(direct::PlaceholderOutbound::new(
                            config.name.clone(),
                            "snell",
                            config.routing_mark,
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
                            config.routing_mark,
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
    /// Returns proxies and optional subscription info from response headers.
    async fn load_proxy_provider(
        name: &str,
        config: &ProxyProviderConfig,
    ) -> Result<(Vec<ProxyConfig>, Option<SubscriptionInfo>)> {
        let mut sub_info = None;
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
                        // Parse subscription-userinfo header
                        sub_info = parse_subscription_userinfo(
                            resp.headers().get("subscription-userinfo"),
                        );
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
                    let resp = reqwest::get(url).await?;
                    sub_info = parse_subscription_userinfo(
                        resp.headers().get("subscription-userinfo"),
                    );
                    resp.text().await?
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

        Ok((parsed.proxies, sub_info))
    }

    /// Get an outbound handler by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.proxies.get(name).cloned()
    }

    /// Get proxy for the given action target name.
    /// Resolves proxy groups to their selected/active proxy, following chains
    /// like Others → Proxy → Auto-UrlTest → actual proxy (up to 10 levels).
    pub fn resolve(&self, target: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.resolve_depth(target, 10)
    }

    fn resolve_depth(&self, target: &str, depth: usize) -> Option<Arc<dyn OutboundHandler>> {
        if depth == 0 {
            return None;
        }

        // mihomo compat: "GLOBAL" is a virtual selector that delegates to the
        // first proxy group. Matches mihomo's proxies["GLOBAL"] behavior.
        if target == "GLOBAL" {
            if let Some(first_gc) = self.group_configs.first() {
                return self.resolve_depth(&first_gc.name, depth - 1);
            }
            // No groups configured — fall through to DIRECT
            return self.proxies.get("DIRECT").cloned();
        }

        // Direct proxy match
        if let Some(proxy) = self.proxies.get(target) {
            return Some(proxy.clone());
        }

        // Proxy group — resolve its selected proxy recursively
        if let Some(group) = self.live_groups.get(target) {
            let selected = group.now();
            if let Some(result) = self.resolve_depth(&selected, depth - 1) {
                return Some(result);
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

    /// Get subscription info for a provider.
    pub fn get_subscription_info(&self, provider_name: &str) -> Option<&SubscriptionInfo> {
        self.subscription_info.get(provider_name)
    }

    /// Get the shared proxy state store (for API and health checks).
    pub fn state_store(&self) -> &Arc<crate::proxy_group::proxy_state::ProxyStateStore> {
        &self.state_store
    }
}

/// Parse the subscription-userinfo header value.
/// Format: "upload=N; download=N; total=N; expire=N"
fn parse_subscription_userinfo(
    header: Option<&reqwest::header::HeaderValue>,
) -> Option<SubscriptionInfo> {
    let value = header?.to_str().ok()?;
    let mut info = SubscriptionInfo::default();
    for part in value.split(';') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            let val = val.trim().parse::<u64>().unwrap_or(0);
            match key.trim() {
                "upload" => info.upload = val,
                "download" => info.download = val,
                "total" => info.total = val,
                "expire" => info.expire = val,
                _ => {}
            }
        }
    }
    Some(info)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub udp: bool,
}
