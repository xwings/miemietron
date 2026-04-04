// Suppress dead_code warnings — modules are scaffolded for future phases.
#![allow(dead_code)]

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

mod api;
mod common;
mod config;
mod conn;
mod dns;
mod inbound;
mod proxy;
mod proxy_group;
mod rules;
mod sniffer;
mod stack;
mod store;
mod transport;
mod tun;

use config::MiemieConfig;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Miemietron - High-performance proxy kernel (Meta compatible)
#[derive(Parser, Debug)]
#[command(name = "mihomo", version, about)]
struct Cli {
    /// Configuration directory (working directory for the core)
    #[arg(short = 'd', env = "CLASH_HOME_DIR")]
    home_dir: Option<PathBuf>,

    /// Configuration file path
    #[arg(short = 'f', env = "CLASH_CONFIG_FILE")]
    config_file: Option<PathBuf>,

    /// Base64-encoded config string
    #[arg(long = "config", env = "CLASH_CONFIG_STRING")]
    config_string: Option<String>,

    /// External controller address
    #[arg(long = "ext-ctl", env = "CLASH_OVERRIDE_EXTERNAL_CONTROLLER")]
    ext_ctl: Option<String>,

    /// External controller unix socket
    #[arg(long = "ext-ctl-unix", env = "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX")]
    ext_ctl_unix: Option<String>,

    /// API secret
    #[arg(long = "secret", env = "CLASH_OVERRIDE_SECRET")]
    secret: Option<String>,

    /// External UI directory
    #[arg(long = "ext-ui", env = "CLASH_OVERRIDE_EXTERNAL_UI_DIR")]
    ext_ui: Option<String>,

    /// Geodata mode
    #[arg(short = 'm', default_value_t = false)]
    geodata_mode: bool,

    /// Test configuration and exit
    #[arg(short = 't', default_value_t = false)]
    test_config: bool,

    /// Print version and exit
    #[arg(short = 'v', long = "version-flag")]
    print_version: bool,
}

fn default_home_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CLASH_HOME_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".config").join("mihomo")
}

fn resolve_config_path(cli: &Cli) -> PathBuf {
    if let Some(ref f) = cli.config_file {
        return f.clone();
    }
    let home = cli.home_dir.clone().unwrap_or_else(default_home_dir);
    home.join("config.yaml")
}

/// Format version string to match mihomo's output exactly.
/// OpenClash parses: `$CLASH -v 2>/dev/null | awk -F ' ' '{print $3}' | head -1`
/// and also greps for "Meta" or "meta" to detect core type.
fn version_string() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    format!("Mihomo Meta v{VERSION} {os}/{arch} (miemietron)")
}

/// Shared application state that supports hot-reload.
///
/// Components behind `parking_lot::RwLock<Arc<T>>` can be swapped atomically
/// on reload. Readers clone the inner `Arc` (cheap) and use it, so existing
/// connections continue with the old state while new connections pick up
/// the new state.
pub struct AppState {
    pub config: parking_lot::RwLock<Arc<MiemieConfig>>,
    pub rule_engine: parking_lot::RwLock<Arc<rules::RuleEngine>>,
    pub proxy_manager: parking_lot::RwLock<Arc<proxy::ProxyManager>>,
    pub dns_resolver: parking_lot::RwLock<Arc<dns::DnsResolver>>,
    pub stats: Arc<conn::StatsManager>,
    pub runtime_config: parking_lot::RwLock<api::RuntimeConfig>,
    pub home_dir: PathBuf,
    pub config_path: parking_lot::RwLock<PathBuf>,
    /// Channel for the API to request a config reload (used by POST /restart).
    pub restart_tx: mpsc::Sender<()>,
}

impl AppState {
    /// Snapshot the current config Arc (cheap clone).
    pub fn config(&self) -> Arc<MiemieConfig> {
        self.config.read().clone()
    }

    /// Snapshot the current rule engine Arc.
    pub fn rule_engine(&self) -> Arc<rules::RuleEngine> {
        self.rule_engine.read().clone()
    }

    /// Snapshot the current proxy manager Arc.
    pub fn proxy_manager(&self) -> Arc<proxy::ProxyManager> {
        self.proxy_manager.read().clone()
    }

    /// Snapshot the current DNS resolver Arc.
    pub fn dns_resolver(&self) -> Arc<dns::DnsResolver> {
        self.dns_resolver.read().clone()
    }

    /// Perform a full hot-reload from a new config.
    /// Builds new RuleEngine, ProxyManager, and DnsResolver, then swaps them in.
    pub async fn reload_from_config(&self, new_config: MiemieConfig) -> Result<()> {
        let home_dir = &self.home_dir;

        // Build new components from the new config
        let new_dns = dns::DnsResolver::new(&new_config.dns).await?;
        let new_rules = rules::RuleEngine::with_home_dir(
            &new_config.rules,
            &new_config.rule_providers,
            home_dir,
        )
        .await?;
        let new_proxies = proxy::ProxyManager::new(
            &new_config.proxies,
            &new_config.proxy_groups,
            &new_config.proxy_providers,
        )
        .await?;

        // If store-selected is enabled, restore saved selections
        let store_selected = new_config
            .profile
            .as_ref()
            .map(|p| p.store_selected)
            .unwrap_or(false);
        if store_selected {
            let saved = store::load_selected(home_dir);
            if !saved.is_empty() {
                new_proxies.apply_saved_selections(&saved);
                info!("Restored {} saved proxy selections", saved.len());
            }
        }

        let rule_count = new_rules.rule_count();
        let proxy_count = new_proxies.proxy_count();

        // Swap in the new components atomically
        {
            let mut rt = self.runtime_config.write();
            if rt.mode != new_config.mode {
                info!(
                    "Config reload: mode changed {} -> {}",
                    rt.mode, new_config.mode
                );
                rt.mode = new_config.mode.clone();
            }
            if rt.log_level != new_config.log_level {
                info!(
                    "Config reload: log-level changed {} -> {}",
                    rt.log_level, new_config.log_level
                );
                rt.log_level = new_config.log_level.clone();
            }
        }

        *self.dns_resolver.write() = Arc::new(new_dns);
        *self.rule_engine.write() = Arc::new(new_rules);
        *self.proxy_manager.write() = Arc::new(new_proxies);
        *self.config.write() = Arc::new(new_config);

        info!(
            "Config reload complete: {} rules, {} proxies",
            rule_count, proxy_count
        );

        Ok(())
    }

    /// Perform a full hot-reload from a config file path.
    pub async fn reload_from_path(&self, path: &std::path::Path) -> Result<()> {
        info!("Reloading config from: {}", path.display());
        let new_config = MiemieConfig::load(path)?;
        self.reload_from_config(new_config).await
    }

    /// Perform a full hot-reload from a YAML string.
    pub async fn reload_from_str(&self, yaml: &str) -> Result<()> {
        let new_config = MiemieConfig::parse_str(yaml)?;
        self.reload_from_config(new_config).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // -v: print version in mihomo-compatible format (before logging init)
    if cli.print_version {
        println!("{}", version_string());
        return Ok(());
    }

    // -d: set working directory (OpenClash always passes -d /etc/openclash)
    if let Some(ref home) = cli.home_dir {
        if home.exists() {
            if let Err(e) = std::env::set_current_dir(home) {
                eprintln!("Failed to chdir to {}: {}", home.display(), e);
            }
        }
    }

    // Load config FIRST so we can use its log-level for tracing init
    let config_path = resolve_config_path(&cli);
    let mut config = MiemieConfig::load(&config_path)?;

    // Initialize logging with the broadcast layer for the /logs API.
    // Honor config's log-level (like mihomo), but RUST_LOG env var overrides.
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let log_level = match config.log_level.as_str() {
            "silent" => "off",
            "error" => "error",
            "warning" | "warn" => "warn",
            "debug" => "debug",
            "trace" => "trace",
            _ => "info",
        };

        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

        let fmt_layer = tracing_subscriber::fmt::layer();

        let broadcast_layer = api::logs::BroadcastLayer::new(api::logs::global_log_broadcast());

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(broadcast_layer)
            .init();
    }

    info!("Loading config from: {}", config_path.display());

    // Apply CLI overrides
    if let Some(ref addr) = cli.ext_ctl {
        config.external_controller = Some(addr.clone());
    }
    if let Some(ref addr) = cli.ext_ctl_unix {
        config.external_controller_unix = Some(addr.clone());
    }
    if let Some(ref s) = cli.secret {
        config.secret = Some(s.clone());
    }

    // -t: test config and exit
    if cli.test_config {
        info!("Configuration test successful");
        return Ok(());
    }

    info!("Starting miemietron {}...", VERSION);

    // Store home_dir for GeoIP/GeoSite loading
    let home_dir = cli.home_dir.clone().unwrap_or_else(default_home_dir);

    let engine = Engine::new(config, home_dir, config_path).await?;
    engine.run().await?;

    Ok(())
}

pub struct Engine {
    config: MiemieConfig,
    home_dir: PathBuf,
    config_path: PathBuf,
}

impl Engine {
    async fn new(config: MiemieConfig, home_dir: PathBuf, config_path: PathBuf) -> Result<Self> {
        Ok(Self {
            config,
            home_dir,
            config_path,
        })
    }

    async fn run(self) -> Result<()> {
        let home_dir = self.home_dir;
        let config_path = self.config_path;

        // Start DNS resolver
        let dns_resolver = Arc::new(dns::DnsResolver::new(&self.config.dns).await?);
        info!("DNS resolver started");

        // Load FakeIP persistence if enabled
        let store_fake_ip = self
            .config
            .profile
            .as_ref()
            .map(|p| p.store_fake_ip)
            .unwrap_or(false);
        let fakeip_path = home_dir.join("cache").join("fakeip.json");
        if store_fake_ip {
            if let Some(parent) = fakeip_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = dns_resolver.load_fakeip(&fakeip_path) {
                warn!("Failed to load FakeIP cache: {}", e);
            }
        }

        // Build rule engine
        let rule_engine = Arc::new(
            rules::RuleEngine::with_home_dir(
                &self.config.rules,
                &self.config.rule_providers,
                &home_dir,
            )
            .await?,
        );
        info!("Rule engine loaded with {} rules", rule_engine.rule_count());

        // Build proxy manager
        let proxy_manager = Arc::new(
            proxy::ProxyManager::new(
                &self.config.proxies,
                &self.config.proxy_groups,
                &self.config.proxy_providers,
            )
            .await?,
        );

        // Restore saved proxy selections if store-selected is enabled
        let store_selected = self
            .config
            .profile
            .as_ref()
            .map(|p| p.store_selected)
            .unwrap_or(false);
        if store_selected {
            let saved = store::load_selected(&home_dir);
            if !saved.is_empty() {
                proxy_manager.apply_saved_selections(&saved);
                info!("Restored {} saved proxy selections", saved.len());
            }
        }

        info!(
            "Proxy manager loaded with {} proxies",
            proxy_manager.proxy_count()
        );

        // Build shared application state
        let stats = Arc::new(conn::StatsManager::new());
        let (restart_tx, mut restart_rx) = mpsc::channel::<()>(1);
        let app_state = Arc::new(AppState {
            config: parking_lot::RwLock::new(Arc::new(self.config.clone())),
            rule_engine: parking_lot::RwLock::new(rule_engine.clone()),
            proxy_manager: parking_lot::RwLock::new(proxy_manager.clone()),
            dns_resolver: parking_lot::RwLock::new(dns_resolver.clone()),
            stats: stats.clone(),
            runtime_config: parking_lot::RwLock::new(api::RuntimeConfig {
                mode: self.config.mode.clone(),
                log_level: self.config.log_level.clone(),
            }),
            home_dir: home_dir.clone(),
            config_path: parking_lot::RwLock::new(config_path.clone()),
            restart_tx,
        });

        // Start connection manager
        let conn_manager = Arc::new(conn::ConnectionManager::new(app_state.clone()));

        // Build runtime config reference for backward compat
        let config = app_state.config();

        // Start API server
        let ext_ctl_addr = config.external_controller.clone();
        let api_secret = config.secret.clone();
        let api_handle = if let Some(ref addr) = ext_ctl_addr {
            let addr = addr.clone();
            let api_state = api::ApiState {
                app: app_state.clone(),
                conn_manager: conn_manager.clone(),
            };
            Some(tokio::spawn(async move {
                if let Err(e) = api::start_server(&addr, api_secret, api_state).await {
                    error!("API server error: {}", e);
                }
            }))
        } else {
            None
        };
        if let Some(ref addr) = ext_ctl_addr {
            info!("API server listening on {}", addr);
        }

        // Start TUN device
        let tun_handle = if config.tun.enable {
            let tun_config = config.tun.clone();
            let cm = conn_manager.clone();
            let dns = dns_resolver.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = tun::run_tun(tun_config, cm, dns).await {
                    error!("TUN error: {}", e);
                }
            }))
        } else {
            info!("TUN mode disabled");
            None
        };

        // Start DNS listener
        let dns_handle = if config.dns.enable {
            let listen = config.dns.listen.clone();
            let resolver = dns_resolver.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = dns::run_dns_server(&listen, resolver).await {
                    error!("DNS server error: {}", e);
                }
            }))
        } else {
            None
        };

        // Start inbound proxy listeners (HTTP, SOCKS5, mixed-port, redir-port, tproxy-port)
        let mut inbound_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        // Shared authentication list for inbound proxy connections
        let auth_list: Arc<Vec<String>> = Arc::new(config.authentication.clone());

        let bind_ip: std::net::IpAddr = if config.allow_lan {
            if config.bind_address == "*" {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                config
                    .bind_address
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            }
        } else {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        };

        if config.mixed_port > 0 {
            let addr = std::net::SocketAddr::new(bind_ip, config.mixed_port);
            let cm = conn_manager.clone();
            let auth = auth_list.clone();
            inbound_handles.push(tokio::spawn(async move {
                if let Err(e) = inbound::run_mixed_proxy(addr, cm, auth).await {
                    error!("Mixed proxy error: {}", e);
                }
            }));
            info!("Mixed proxy (HTTP+SOCKS5) on {}", addr);
        }

        if config.port > 0 {
            let addr = std::net::SocketAddr::new(bind_ip, config.port);
            let cm = conn_manager.clone();
            let auth = auth_list.clone();
            inbound_handles.push(tokio::spawn(async move {
                if let Err(e) = inbound::http::run_http_proxy(addr, cm, auth).await {
                    error!("HTTP proxy error: {}", e);
                }
            }));
            info!("HTTP proxy on {}", addr);
        }

        if config.socks_port > 0 {
            let addr = std::net::SocketAddr::new(bind_ip, config.socks_port);
            let cm = conn_manager.clone();
            let auth = auth_list.clone();
            inbound_handles.push(tokio::spawn(async move {
                if let Err(e) = inbound::socks::run_socks_proxy(addr, cm, auth).await {
                    error!("SOCKS5 proxy error: {}", e);
                }
            }));
            info!("SOCKS5 proxy on {}", addr);
        }

        // redir-port: transparent TCP proxy for iptables REDIRECT (used by OpenClash)
        if config.redir_port > 0 {
            let port = config.redir_port;
            let cm = conn_manager.clone();
            inbound_handles.push(tokio::spawn(async move {
                if let Err(e) = inbound::redir::run_redir_listener(port, cm).await {
                    error!("Redir proxy error: {}", e);
                }
            }));
            info!(
                "Transparent TCP (redir-port) on 0.0.0.0:{}",
                config.redir_port
            );
        }

        // tproxy-port: transparent UDP proxy for iptables TPROXY (used by OpenClash)
        if config.tproxy_port > 0 {
            let port = config.tproxy_port;
            let cm = conn_manager.clone();
            let dns = dns_resolver.clone();
            inbound_handles.push(tokio::spawn(async move {
                if let Err(e) = tun::run_tproxy_udp_listener(port, cm, dns).await {
                    error!("TPROXY UDP proxy error: {}", e);
                }
            }));
            info!(
                "Transparent UDP (tproxy-port) on 0.0.0.0:{}",
                config.tproxy_port
            );
        }

        // Spawn background health checks for url-test and fallback groups
        let health_handles = proxy_group::health::spawn_health_checks(
            proxy_manager.list_live_groups(),
            proxy_manager.proxies_map().clone(),
        );
        if !health_handles.is_empty() {
            info!("Spawned {} health check tasks", health_handles.len());
        }

        // Spawn periodic FakeIP persistence task (every 60s)
        let fakeip_save_handle = if store_fake_ip {
            let resolver = dns_resolver.clone();
            let path = fakeip_path.clone();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    if let Err(e) = resolver.save_fakeip(&path) {
                        warn!("Failed to save FakeIP cache: {}", e);
                    }
                }
            }))
        } else {
            None
        };

        info!("Miemietron started successfully");

        // Wait for shutdown, reload signal, or API-triggered restart
        loop {
            tokio::select! {
                sig = shutdown_or_reload_signal() => {
                    match sig {
                        Signal::Shutdown => {
                            info!("Shutting down...");
                            break;
                        }
                        Signal::Reload => {
                            info!("SIGHUP received, performing full config reload...");
                            let path = app_state.config_path.read().clone();
                            if let Err(e) = app_state.reload_from_path(&path).await {
                                error!("Config reload failed: {}", e);
                            }
                        }
                    }
                }
                _ = restart_rx.recv() => {
                    info!("Restart requested via API, performing full config reload...");
                    let path = app_state.config_path.read().clone();
                    if let Err(e) = app_state.reload_from_path(&path).await {
                        error!("Config reload (restart) failed: {}", e);
                    }
                }
            }
        }

        // Save FakeIP state on shutdown
        if store_fake_ip {
            if let Err(e) = dns_resolver.save_fakeip(&fakeip_path) {
                warn!("Failed to save FakeIP cache on shutdown: {}", e);
            } else {
                info!("FakeIP cache saved");
            }
        }

        // Cleanup
        if let Some(h) = fakeip_save_handle {
            h.abort();
        }
        for h in inbound_handles {
            h.abort();
        }
        for h in health_handles {
            h.abort();
        }
        if let Some(h) = tun_handle {
            h.abort();
        }
        if let Some(h) = api_handle {
            h.abort();
        }
        if let Some(h) = dns_handle {
            h.abort();
        }

        // Clean up iptables and routing rules
        if config.tun.enable {
            if let Err(e) = tun::cleanup(&config.tun).await {
                warn!("TUN cleanup error: {}", e);
            }
        }

        info!("Goodbye!");
        Ok(())
    }
}

enum Signal {
    Shutdown,
    Reload,
}

async fn shutdown_or_reload_signal() -> Signal {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        Signal::Shutdown
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        Signal::Shutdown
    };

    #[cfg(unix)]
    let hangup = async {
        signal::unix::signal(signal::unix::SignalKind::hangup())
            .expect("failed to install SIGHUP handler")
            .recv()
            .await;
        Signal::Reload
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<Signal>();

    #[cfg(not(unix))]
    let hangup = std::future::pending::<Signal>();

    tokio::select! {
        s = ctrl_c => s,
        s = terminate => s,
        s = hangup => s,
    }
}
