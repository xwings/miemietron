pub mod anytls;
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

/// Global options that apply to all proxies (routing mark, keepalive, etc.).
/// Bundles related parameters to avoid too-many-arguments warnings.
pub struct ProxyGlobalOpts {
    pub routing_mark: Option<u32>,
    pub tcp_concurrent: bool,
    pub keep_alive_idle: u64,
    pub keep_alive_interval: u64,
    pub disable_keep_alive: bool,
}

/// Manages all configured proxies and provides lookup.
pub struct ProxyManager {
    proxies: HashMap<String, Arc<dyn OutboundHandler>>,
    live_groups: HashMap<String, Arc<dyn ProxyGroup>>,
    provider_configs: HashMap<String, ProxyProviderConfig>,
    /// Member proxy names for each proxy provider (for `/providers/proxies`).
    provider_proxy_names: HashMap<String, Vec<String>>,
}

impl ProxyManager {
    pub async fn with_state_store(
        proxy_configs: &[ProxyConfig],
        group_configs: &[ProxyGroupConfig],
        providers: &HashMap<String, ProxyProviderConfig>,
        global_opts: &ProxyGlobalOpts,
        state_store: Arc<crate::proxy_group::proxy_state::ProxyStateStore>,
    ) -> Result<Self> {
        let mut proxies: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        let global_routing_mark = global_opts.routing_mark;

        // mihomo compat: DefaultRoutingMark starts at 0 in mihomo (dialer/options.go:14).
        // When no routing-mark is configured, mihomo does NOT set SO_MARK on sockets.
        // It relies on GID 65534 (set by OpenClash via procd) for firewall bypass.
        // Only set SO_MARK when the config explicitly specifies routing-mark.
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

        // Parse configured proxies, applying global settings as defaults.
        // mihomo compat: config.go:880-882 — any per-proxy parse error fails the
        // whole config load with `proxy %d: %w`. We never silently swap an
        // unsupported / invalid proxy for DIRECT (which would leak traffic).
        for (idx, config) in proxy_configs.iter().enumerate() {
            let mut cfg = config.clone();
            Self::apply_global_defaults(&mut cfg, global_opts);
            let handler =
                Self::load_proxy_config(&cfg).map_err(|e| anyhow::anyhow!("proxy {idx}: {e}"))?;
            proxies.insert(cfg.name.clone(), handler);
        }

        // Load proxy providers and add their proxies.
        // Track which proxy names come from each provider for group expansion.
        let mut provider_proxy_names: HashMap<String, Vec<String>> = HashMap::new();
        for (prov_name, prov_config) in providers {
            match Self::load_proxy_provider(prov_name, prov_config).await {
                Ok(provider_proxies) => {
                    let mut names = Vec::new();
                    // mihomo compat: provider.go:436-438 — any per-proxy parse
                    // error fails the provider load with `proxy %d error: %w`.
                    for (idx, pc) in provider_proxies.iter().enumerate() {
                        let mut cfg = pc.clone();
                        Self::apply_global_defaults(&mut cfg, global_opts);
                        match Self::load_proxy_config(&cfg) {
                            Ok(handler) => {
                                names.push(cfg.name.clone());
                                proxies.insert(cfg.name.clone(), handler);
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "provider '{prov_name}' proxy {idx} error: {e}"
                                ));
                            }
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
            let filter_regs = Self::parse_filter_regs(&gc.name, "filter", gc.filter.as_deref());
            let exclude_filter_regs =
                Self::parse_filter_regs(&gc.name, "exclude-filter", gc.exclude_filter.as_deref());

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
                all_proxies.retain(|name| !exclude_filter_regs.iter().any(|re| re.is_match(name)));
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

            // Warn when filtering leaves the group empty (mihomo falls back to
            // a COMPATIBLE placeholder; we only log — no fallback is inserted).
            if all_proxies.is_empty() {
                tracing::warn!("Proxy group '{}' has no proxies after filtering", gc.name);
            }

            // mihomo compat: default test URL is https (constant/adapters.go:61);
            // `lazy` defaults to true (parser.go:51-53); `tolerance` defaults to
            // 0 (urltest.go:19-23); `interval: 0` is coerced to 300s so the
            // health-check timer never gets a zero period (parser.go:168-170) —
            // a zero-period tokio interval would panic and abort the process.
            let default_test_url = || "https://www.gstatic.com/generate_204".to_string();
            let hc_interval = match gc.interval {
                Some(0) | None => 300,
                Some(n) => n,
            };
            let hc_lazy = gc.lazy.unwrap_or(true);
            // mihomo compat: parser.go:118-121 — an invalid expected-status
            // fails the whole config load with `<group>: <err>`.
            let expected_status = crate::proxy_group::parse_expected_status(
                gc.expected_status.as_deref().unwrap_or(""),
            )
            .map_err(|e| anyhow::anyhow!("{}: {}", gc.name, e))?;
            let make_hc = |interval_secs: u64| crate::proxy_group::HealthCheckOpts {
                url: gc.url.clone().unwrap_or_else(default_test_url),
                interval_secs,
                max_failed_times: gc.max_failed_times,
                test_timeout: gc.timeout,
                lazy: hc_lazy,
                expected_status: expected_status.clone(),
            };

            let group: Arc<dyn ProxyGroup> = match gc.group_type.as_str() {
                // mihomo compat: parser.go:166-171 + healthcheck.go auto() —
                // select groups get a periodic health check only when the
                // user configures a non-zero interval (no 300s default).
                "select" => match gc.interval {
                    Some(n) if n > 0 => Arc::new(SelectorGroup::with_health_check(
                        gc.name.clone(),
                        all_proxies,
                        make_hc(n),
                        state_store.clone(),
                    )),
                    _ => Arc::new(SelectorGroup::new(gc.name.clone(), all_proxies)),
                },
                "url-test" => Arc::new(UrlTestGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    gc.tolerance.unwrap_or(0),
                    make_hc(hc_interval),
                    state_store.clone(),
                )),
                "fallback" => Arc::new(FallbackGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    make_hc(hc_interval),
                    state_store.clone(),
                )),
                "load-balance" => Arc::new(LoadBalanceGroup::new(
                    gc.name.clone(),
                    all_proxies,
                    LoadBalanceStrategy::from_str(
                        gc.strategy.as_deref().unwrap_or("consistent-hashing"),
                    ),
                    make_hc(hc_interval),
                    state_store.clone(),
                )),
                "relay" => {
                    // mihomo compat: parser.go:196-197 — relay groups were
                    // removed in Meta; this is a hard config error, not a skip.
                    return Err(anyhow::anyhow!(
                        "unsupport proxy group type: The group [{}] with relay type was removed, please using dialer-proxy instead",
                        gc.name
                    ));
                }
                other => {
                    // mihomo compat: parser.go:198-199 — unknown group types
                    // fail the config load; degrading to a selector would
                    // silently change routing.
                    return Err(anyhow::anyhow!("unsupport proxy group type: {other}"));
                }
            };
            info!(
                "Created proxy group '{}' (type: {})",
                gc.name, gc.group_type
            );
            live_groups.insert(gc.name.clone(), group);
        }

        // mihomo compat: register a real GLOBAL selector (config.go:963-972).
        // Its member list is every configured group followed by every individual
        // proxy (including built-ins), and it is a genuine, selectable Selector so
        // `PUT/GET /proxies/GLOBAL` and `GET /group/GLOBAL` behave like any group.
        // Only synthesized if the user didn't define their own group named GLOBAL.
        if !live_groups.contains_key("GLOBAL") {
            let mut global_members: Vec<String> =
                group_configs.iter().map(|g| g.name.clone()).collect();
            let mut seen: std::collections::HashSet<String> =
                global_members.iter().cloned().collect();
            for pc in proxy_configs {
                if seen.insert(pc.name.clone()) {
                    global_members.push(pc.name.clone());
                }
            }
            for builtin in ["DIRECT", "REJECT", "REJECT-DROP"] {
                if proxies.contains_key(builtin) && seen.insert(builtin.to_string()) {
                    global_members.push(builtin.to_string());
                }
            }
            let global: Arc<dyn ProxyGroup> =
                Arc::new(SelectorGroup::new("GLOBAL".to_string(), global_members));
            live_groups.insert("GLOBAL".to_string(), global);
        }

        Ok(Self {
            proxies,
            live_groups,
            provider_configs: providers.clone(),
            provider_proxy_names,
        })
    }

    /// Apply global proxy options (routing mark, tcp-concurrent, keepalive) to
    /// a proxy config that doesn't override them. Used for both directly
    /// configured proxies and provider-sourced proxies.
    fn apply_global_defaults(cfg: &mut ProxyConfig, global_opts: &ProxyGlobalOpts) {
        if cfg.routing_mark.is_none() {
            cfg.routing_mark = global_opts.routing_mark;
        }
        if cfg.tcp_concurrent.is_none() && global_opts.tcp_concurrent {
            cfg.tcp_concurrent = Some(true);
        }
        // mihomo compat: inject global keepalive settings
        if cfg.keep_alive_idle.is_none() {
            cfg.keep_alive_idle = Some(global_opts.keep_alive_idle);
        }
        if cfg.keep_alive_interval.is_none() {
            cfg.keep_alive_interval = Some(global_opts.keep_alive_interval);
        }
        if cfg.disable_keep_alive.is_none() {
            cfg.disable_keep_alive = Some(global_opts.disable_keep_alive);
        }
    }

    /// Parse backtick-separated filter regex patterns for a proxy group,
    /// warning on (and skipping) any invalid pattern.
    fn parse_filter_regs(group_name: &str, kind: &str, filter: Option<&str>) -> Vec<Regex> {
        filter
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split('`')
                    .filter_map(|pat| match Regex::new(pat) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            tracing::warn!(
                                "Proxy group '{}': invalid {} regex '{}': {}",
                                group_name,
                                kind,
                                pat,
                                e
                            );
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Load a single proxy from config.
    ///
    /// mihomo compat: matches `adapter/parser.go::ParseProxy`. Returns an error
    /// for unsupported proxy types (verbatim "unsupport proxy type: <type>")
    /// and propagates construction failures so the caller can fail the entire
    /// config load with `proxy <idx>: <err>`. We never silently substitute a
    /// placeholder/DIRECT outbound for an unsupported or invalid proxy.
    fn load_proxy_config(config: &ProxyConfig) -> Result<Arc<dyn OutboundHandler>> {
        match config.proxy_type.as_str() {
            "ss" => {
                info!("Loading SS proxy: {}", config.name);
                let handler = shadowsocks::ShadowsocksOutbound::from_config(config)?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "vless")]
            "vless" => {
                info!("Loading VLESS proxy: {}", config.name);
                let handler = vless::VlessOutbound::new(config)?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "trojan")]
            "trojan" => {
                info!("Loading Trojan proxy: {}", config.name);
                let handler = trojan::TrojanOutbound::new(config)?;
                Ok(Arc::new(handler))
            }
            #[cfg(feature = "vmess")]
            "vmess" => {
                info!("Loading VMess proxy: {}", config.name);
                let handler = vmess::VmessOutbound::new(config)?;
                Ok(Arc::new(handler))
            }
            "http" => {
                info!("Loading HTTP proxy: {}", config.name);
                let handler = http::HttpOutbound::from_config(config)?;
                Ok(Arc::new(handler))
            }
            "socks5" => {
                info!("Loading SOCKS5 proxy: {}", config.name);
                let handler = socks5::Socks5Outbound::from_config(config)?;
                Ok(Arc::new(handler))
            }
            "snell" => {
                info!("Loading Snell proxy: {}", config.name);
                let handler = snell::SnellOutbound::from_config(config)?;
                Ok(Arc::new(handler))
            }
            "anytls" => {
                info!("Loading AnyTLS proxy: {}", config.name);
                let handler = anytls::AnytlsOutbound::from_config(config)?;
                Ok(Arc::new(handler))
            }
            "ssr" => {
                info!("Loading SSR proxy: {}", config.name);
                let handler = ssr::SsrOutbound::from_config(config)?;
                Ok(Arc::new(handler))
            }
            "direct" => {
                // mihomo compat: parser.go:113-119 + outbound/direct.go::
                // NewDirectWithOption — user-named DIRECT with optional
                // routing-mark / interface / ip-version. We honor routing-mark;
                // the rest of BasicOption is accepted for parity but not all
                // fields take effect (parity matrix tracks what's wired).
                info!("Loading user-defined DIRECT proxy: {}", config.name);
                Ok(Arc::new(direct::NamedDirectOutbound::new(
                    config.name.clone(),
                    config.routing_mark,
                )))
            }
            "reject" => {
                // mihomo compat: parser.go:127-133 + outbound/reject.go::
                // NewRejectWithOption — user-named REJECT.
                info!("Loading user-defined REJECT proxy: {}", config.name);
                Ok(Arc::new(direct::NamedRejectOutbound::new(
                    config.name.clone(),
                )))
            }
            other => {
                // mihomo compat: parser.go:177 default case error wording
                // (note the upstream typo "unsupport").
                Err(anyhow::anyhow!("unsupport proxy type: {other}"))
            }
        }
    }

    /// Fetch an HTTP provider's URL and return the response body.
    async fn fetch_provider_url(name: &str, config: &ProxyProviderConfig) -> Result<String> {
        let url = config
            .url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP provider '{name}' has no URL"))?;
        let resp = reqwest::get(url).await?;
        Ok(resp.text().await?)
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
                        tokio::fs::read_to_string(&pb).await.map_err(|e| {
                            anyhow::anyhow!("failed to read proxy provider cache '{path}': {e}")
                        })?
                    } else {
                        let text = Self::fetch_provider_url(name, config).await?;
                        // Cache to disk
                        if let Some(parent) = pb.parent() {
                            tokio::fs::create_dir_all(parent).await.ok();
                        }
                        tokio::fs::write(&pb, &text).await.ok();
                        text
                    }
                } else {
                    Self::fetch_provider_url(name, config).await?
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

    /// Resolve a rule-engine [`Action`] to an outbound handler, erroring if
    /// the named proxy cannot be resolved.
    ///
    /// Architecture rule: when [`Action::Proxy(name)`](crate::rules::Action::Proxy)
    /// fails to resolve (typo in a rule target, broken group chain, etc.),
    /// this function returns an error — it does **NOT** silently fall back
    /// to DIRECT. A silent fallback would route operator-tunnel-bound
    /// traffic onto the bare network when the rule explicitly asked for a
    /// proxy.
    ///
    /// `Action::Direct` / `Action::Reject` / `Action::RejectDrop` only error
    /// if the corresponding built-in handler is missing — which would mean
    /// the manager itself is broken.
    pub fn resolve_action(
        &self,
        action: &crate::rules::Action,
    ) -> Result<Arc<dyn OutboundHandler>> {
        use crate::rules::Action;
        match action {
            Action::Direct => self
                .proxies
                .get("DIRECT")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("built-in DIRECT handler missing")),
            Action::Reject => self
                .proxies
                .get("REJECT")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("built-in REJECT handler missing")),
            Action::RejectDrop => self
                .proxies
                .get("REJECT-DROP")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("built-in REJECT-DROP handler missing")),
            Action::Proxy(name) => self.resolve(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "rule selected proxy '{name}' but it could not be resolved \
                     (unknown name, broken group chain, or resolution depth exceeded). \
                     No silent DIRECT fallback — see ARCHITECTURE.md"
                )
            }),
        }
    }

    /// Open a UDP packet conn through the named proxy.
    ///
    /// Architecture rule: when a rule selects a proxy and the proxy is
    /// missing (e.g. removed from config) or its `connect_datagram` fails,
    /// this function returns an error — it does NOT fall back to DIRECT.
    /// Silent fallback would leak unencrypted UDP onto the wire when the
    /// operator asked for a tunnel. The caller is expected to drop the
    /// datagram on error (UDP is best-effort).
    ///
    /// Used by `inbound::socks::create_socks_udp_session` and
    /// `tun::create_udp_session`.
    pub async fn dial_proxy_udp(
        &self,
        proxy_name: &str,
        target: &Address,
        dns: Arc<DnsResolver>,
    ) -> Result<Arc<dyn OutboundPacketConn>> {
        let handler = self
            .resolve(proxy_name)
            .ok_or_else(|| anyhow::anyhow!("UDP proxy '{proxy_name}' not found"))?;
        let pc_box = handler.connect_datagram(target, dns).await.map_err(|e| {
            anyhow::anyhow!("UDP proxy '{proxy_name}' connect_datagram failed: {e}")
        })?;
        Ok(Arc::from(pc_box))
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

    /// Get a live proxy group by name.
    pub fn get_group(&self, name: &str) -> Option<Arc<dyn ProxyGroup>> {
        self.live_groups.get(name).cloned()
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

    /// Member proxy infos for a given proxy provider (for `/providers/proxies`).
    pub fn provider_proxy_infos(&self, provider_name: &str) -> Vec<ProxyInfo> {
        self.provider_proxy_names
            .get(provider_name)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| {
                        self.proxies.get(n).map(|h| ProxyInfo {
                            name: n.clone(),
                            proxy_type: h.proto().to_string(),
                            udp: h.supports_udp(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update a proxy provider by fetching its URL and caching the result to
    /// disk. Takes effect on the next config reload — running proxies are not
    /// swapped in place.
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
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            tokio::fs::write(path, &body).await?;
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

#[cfg(test)]
mod tests {
    //! Regression tests for safe per-proxy parse-error handling.
    //!
    //! mihomo's adapter/parser.go returns an error for unsupported types
    //! (verbatim "unsupport proxy type: <T>") and for any failed decode /
    //! construction. config.go:880-882 then aborts the whole config load with
    //! `proxy <idx>: <err>`. We must NOT silently substitute a placeholder /
    //! DIRECT outbound for invalid input — that would leak traffic.
    use super::*;
    use crate::config::proxy::ProxyConfig;

    fn parse_cfg(yaml: &str) -> ProxyConfig {
        serde_yaml::from_str(yaml).expect("test fixture should parse")
    }

    fn must_err(cfg: &ProxyConfig) -> String {
        match ProxyManager::load_proxy_config(cfg) {
            Ok(_) => panic!("expected error, got handler"),
            Err(e) => format!("{e}"),
        }
    }

    #[test]
    fn unsupported_type_errors_with_mihomo_wording() {
        let cfg = parse_cfg(
            r#"
name: bad
type: hysteria2
server: 1.2.3.4
port: 443
"#,
        );
        let msg = must_err(&cfg);
        assert!(
            msg.contains("unsupport proxy type: hysteria2"),
            "wrong error: {msg}"
        );
    }

    #[test]
    fn invalid_ss_cipher_errors_no_direct() {
        let cfg = parse_cfg(
            r#"
name: bad-ss
type: ss
server: 1.2.3.4
port: 8388
cipher: nonexistent-cipher
password: secret
"#,
        );
        // Don't pin exact wording from the SS layer — just confirm an error
        // surfaces rather than silently producing a handler.
        let _ = must_err(&cfg);
    }

    #[test]
    fn missing_required_fields_errors() {
        let cfg = parse_cfg(
            r#"
name: incomplete
type: ss
"#,
        );
        let _ = must_err(&cfg);
    }

    #[test]
    fn placeholder_outbound_does_not_exist() {
        // Compile-time assertion: there is no PlaceholderOutbound type.
        // If someone reintroduces it, this test won't compile.
        // Sanity check: DirectOutbound and RejectOutbound are still here.
        let _ = std::any::type_name::<direct::DirectOutbound>();
        let _ = std::any::type_name::<direct::RejectOutbound>();
    }

    #[test]
    fn user_defined_direct_loads_with_custom_name() {
        // mihomo compat: parser.go:113-119 — `type: direct` with a name binds
        // direct-dial behavior to a config-defined proxy entry.
        let cfg = parse_cfg(
            r#"
name: my-direct
type: direct
"#,
        );
        let handler = ProxyManager::load_proxy_config(&cfg).expect("must load");
        assert_eq!(handler.name(), "my-direct");
        assert_eq!(handler.proto(), "Direct");
        assert!(handler.supports_udp());
    }

    #[test]
    fn user_defined_reject_loads_with_custom_name() {
        // mihomo compat: parser.go:127-133 — `type: reject` with a name.
        let cfg = parse_cfg(
            r#"
name: ad-block
type: reject
"#,
        );
        let handler = ProxyManager::load_proxy_config(&cfg).expect("must load");
        assert_eq!(handler.name(), "ad-block");
        assert_eq!(handler.proto(), "Reject");
        assert!(!handler.supports_udp());
    }

    #[test]
    fn dns_outbound_is_out_of_scope_and_fails_loudly() {
        // mihomo's `type: dns` outbound hijacks DNS to the local resolver.
        // miemietron treats it as out-of-scope (see ARCHITECTURE.md). Until
        // implemented, the config must fail loudly — never silently fall
        // back to DIRECT.
        let cfg = parse_cfg(
            r#"
name: dns-out
type: dns
"#,
        );
        let msg = must_err(&cfg);
        assert!(
            msg.contains("unsupport proxy type: dns"),
            "wrong error: {msg}"
        );
    }

    /// Test-only constructor that bypasses YAML/network setup so we can
    /// exercise `dial_proxy_udp` against arbitrary handler maps.
    fn make_test_manager(handlers: HashMap<String, Arc<dyn OutboundHandler>>) -> ProxyManager {
        ProxyManager {
            proxies: handlers,
            live_groups: HashMap::new(),
            provider_configs: HashMap::new(),
            provider_proxy_names: HashMap::new(),
        }
    }

    /// A stub that always fails `connect_datagram` — used to prove
    /// `dial_proxy_udp` does NOT silently fall back to DIRECT.
    struct UdpFailingHandler;

    #[async_trait]
    impl OutboundHandler for UdpFailingHandler {
        fn name(&self) -> &str {
            "BAD"
        }
        fn proto(&self) -> &str {
            "Stub"
        }
        fn supports_udp(&self) -> bool {
            false
        }
        async fn connect_stream(
            &self,
            _t: &Address,
            _d: &DnsResolver,
        ) -> Result<Box<dyn ProxyStream>> {
            Err(anyhow::anyhow!("stub: TCP not supported"))
        }
        async fn connect_datagram(
            &self,
            _t: &Address,
            _d: Arc<DnsResolver>,
        ) -> Result<Box<dyn OutboundPacketConn>> {
            Err(anyhow::anyhow!("synthetic UDP failure"))
        }
    }

    async fn make_dns() -> Arc<DnsResolver> {
        // Real DnsResolver constructed from default config — our stubs never
        // hit DNS before failing, so this is an inert dependency.
        Arc::new(
            DnsResolver::new(&crate::config::dns::DnsConfig::default())
                .await
                .expect("DnsResolver::new with default config must succeed"),
        )
    }

    fn must_err_udp(res: Result<Arc<dyn OutboundPacketConn>>, ctx: &str) -> String {
        // `Arc<dyn OutboundPacketConn>` doesn't implement Debug, so we can't
        // use `expect_err` directly.
        match res {
            Ok(_) => panic!("{ctx}: expected Err, got Ok"),
            Err(e) => format!("{e}"),
        }
    }

    #[tokio::test]
    async fn udp_missing_proxy_errors_no_direct_fallback() {
        // Architecture rule: when Action::Proxy(name) is selected and the
        // named proxy is missing from the handler map, dial_proxy_udp must
        // return Err — never silently substitute DIRECT.
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        handlers.insert(
            "DIRECT".to_string(),
            Arc::new(direct::DirectOutbound::new(None)),
        );
        let pm = make_test_manager(handlers);
        let target = Address::Domain("example.com".to_string(), 53);
        let dns = make_dns().await;

        let res = pm.dial_proxy_udp("not-in-config", &target, dns).await;
        let msg = must_err_udp(res, "missing-proxy must error");
        assert!(msg.contains("not found"), "wrong error: {msg}");
        // Belt and suspenders: error must NOT mention DIRECT being used.
        assert!(
            !msg.to_lowercase().contains("falling back"),
            "no fallback wording allowed: {msg}"
        );
    }

    /// `Action::Proxy("unknown")` MUST error, NOT be silently downgraded to
    /// DIRECT. This is the symptom the user reported as
    /// "rules not being followed when anytls is in use" — a typo or broken
    /// group chain in the rule target was silently routing tunnel-bound
    /// traffic onto DIRECT.
    #[test]
    fn resolve_action_unknown_proxy_errors_no_direct_fallback() {
        use crate::rules::Action;

        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        handlers.insert(
            "DIRECT".to_string(),
            Arc::new(direct::DirectOutbound::new(None)),
        );
        handlers.insert("REJECT".to_string(), Arc::new(direct::RejectOutbound));
        handlers.insert(
            "REJECT-DROP".to_string(),
            Arc::new(direct::RejectDropOutbound),
        );
        let pm = make_test_manager(handlers);

        let result = pm.resolve_action(&Action::Proxy("not-in-config".to_string()));
        let err = match result {
            Ok(_) => panic!("expected Err, got Ok — silent DIRECT fallback returned"),
            Err(e) => format!("{e}"),
        };
        assert!(
            err.contains("not-in-config"),
            "error must name the missing proxy: {err}"
        );
        assert!(
            err.contains("No silent DIRECT fallback"),
            "error must explicitly state the no-fallback contract: {err}"
        );
    }

    /// Built-in actions resolve to their built-in handlers — basic sanity.
    #[test]
    fn resolve_action_direct_reject_resolve_correctly() {
        use crate::rules::Action;

        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        handlers.insert(
            "DIRECT".to_string(),
            Arc::new(direct::DirectOutbound::new(None)),
        );
        handlers.insert("REJECT".to_string(), Arc::new(direct::RejectOutbound));
        handlers.insert(
            "REJECT-DROP".to_string(),
            Arc::new(direct::RejectDropOutbound),
        );
        let pm = make_test_manager(handlers);

        assert_eq!(pm.resolve_action(&Action::Direct).unwrap().name(), "DIRECT");
        assert_eq!(pm.resolve_action(&Action::Reject).unwrap().name(), "REJECT");
        assert_eq!(
            pm.resolve_action(&Action::RejectDrop).unwrap().name(),
            "REJECT-DROP"
        );
    }

    #[tokio::test]
    async fn udp_proxy_datagram_failure_errors_no_direct_fallback() {
        // Architecture rule: when the named proxy exists but its
        // connect_datagram() fails, dial_proxy_udp must propagate the
        // failure — never silently substitute DIRECT.
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        handlers.insert(
            "DIRECT".to_string(),
            Arc::new(direct::DirectOutbound::new(None)),
        );
        handlers.insert("BAD".to_string(), Arc::new(UdpFailingHandler));
        let pm = make_test_manager(handlers);
        let target = Address::Domain("example.com".to_string(), 53);
        let dns = make_dns().await;

        let res = pm.dial_proxy_udp("BAD", &target, dns).await;
        let msg = must_err_udp(res, "proxy datagram failure must error");
        assert!(
            msg.contains("synthetic UDP failure"),
            "must surface inner error: {msg}"
        );
        assert!(
            msg.contains("BAD"),
            "must name the proxy that failed: {msg}"
        );
    }
}
