// Suppress dead_code warnings — modules are scaffolded for future phases.
#![allow(dead_code)]

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::signal;
use tracing::{error, info, warn};

mod api;
mod common;
mod config;
mod conn;
mod dns;
mod proxy;
mod proxy_group;
mod rules;
mod sniffer;
mod stack;
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // -v: print version in mihomo-compatible format
    // OpenClash runs: `$CLASH -v | awk '{print $3}'` to extract version
    // OpenClash runs: `$CLASH -v | grep 'meta'` to detect Meta core
    if cli.print_version {
        println!("{}", version_string());
        return Ok(());
    }

    // -d: set working directory (OpenClash always passes -d /etc/openclash)
    if let Some(ref home) = cli.home_dir {
        if home.exists() {
            if let Err(e) = std::env::set_current_dir(home) {
                warn!("Failed to chdir to {}: {}", home.display(), e);
            }
        }
    }

    let config_path = resolve_config_path(&cli);
    info!("Loading config from: {}", config_path.display());

    let mut config = MiemieConfig::load(&config_path)?;

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

    let engine = Engine::new(config, home_dir).await?;
    engine.run().await?;

    Ok(())
}

pub struct Engine {
    config: MiemieConfig,
    home_dir: PathBuf,
}

impl Engine {
    async fn new(config: MiemieConfig, home_dir: PathBuf) -> Result<Self> {
        Ok(Self { config, home_dir })
    }

    async fn run(self) -> Result<()> {
        let config = std::sync::Arc::new(self.config);
        let _home_dir = self.home_dir;

        // Start DNS resolver
        let dns_resolver = std::sync::Arc::new(dns::DnsResolver::new(&config.dns).await?);
        info!("DNS resolver started");

        // Build rule engine
        let rule_engine = std::sync::Arc::new(
            rules::RuleEngine::new(&config.rules, &config.rule_providers).await?,
        );
        info!("Rule engine loaded with {} rules", rule_engine.rule_count());

        // Build proxy manager
        let proxy_manager = std::sync::Arc::new(
            proxy::ProxyManager::new(
                &config.proxies,
                &config.proxy_groups,
                &config.proxy_providers,
            )
            .await?,
        );
        info!(
            "Proxy manager loaded with {} proxies",
            proxy_manager.proxy_count()
        );

        // Start connection manager
        let stats = std::sync::Arc::new(conn::StatsManager::new());
        let conn_manager = std::sync::Arc::new(conn::ConnectionManager::new(
            dns_resolver.clone(),
            rule_engine.clone(),
            proxy_manager.clone(),
            stats.clone(),
            config.clone(),
        ));

        // Start API server
        let ext_ctl_addr = config.external_controller.clone();
        let api_secret = config.secret.clone();
        let api_handle = if let Some(ref addr) = ext_ctl_addr {
            let addr = addr.clone();
            let api_state = api::ApiState {
                config: config.clone(),
                proxy_manager: proxy_manager.clone(),
                rule_engine: rule_engine.clone(),
                conn_manager: conn_manager.clone(),
                stats: stats.clone(),
                dns_resolver: dns_resolver.clone(),
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

        info!("Miemietron started successfully");

        // Wait for shutdown or reload signal
        loop {
            let sig = shutdown_or_reload_signal().await;
            match sig {
                Signal::Shutdown => {
                    info!("Shutting down...");
                    break;
                }
                Signal::Reload => {
                    info!("SIGHUP received, reloading config...");
                    // TODO: implement full hot-reload (re-parse config, rebuild rules/proxies)
                    // For now, log it — OpenClash expects SIGHUP to be handled
                    info!(
                        "Config reload not yet fully implemented, continuing with current config"
                    );
                }
            }
        }

        // Cleanup
        if let Some(h) = tun_handle {
            h.abort();
        }
        if let Some(h) = api_handle {
            h.abort();
        }
        if let Some(h) = dns_handle {
            h.abort();
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
