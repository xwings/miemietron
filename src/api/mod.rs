pub mod auth;
pub mod configs;
pub mod connections;
pub mod dns_api;
pub mod logs;
pub mod proxies;
pub mod rules_api;
pub mod traffic;
pub mod ui;
pub mod version;

use anyhow::Result;
use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{info, warn};

use crate::conn::ConnectionManager;
use crate::AppState;

/// Mutable runtime configuration that can be changed via PATCH /configs.
pub struct RuntimeConfig {
    pub mode: String,
    pub log_level: String,
}

/// Shared state for all API handlers.
///
/// Holds a reference to the shared `AppState` (which supports hot-reload)
/// and the connection manager.
#[derive(Clone)]
pub struct ApiState {
    pub app: Arc<AppState>,
    pub conn_manager: Arc<ConnectionManager>,
}

pub async fn start_server(addr: &str, secret: Option<String>, state: ApiState) -> Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Auto-download UI if external-ui is configured but directory is empty/missing
    let config = state.app.config();
    if let Some(ui_dir) = ui::resolve_ui_dir(&config) {
        let needs_download = !ui_dir.exists()
            || ui_dir
                .read_dir()
                .map(|mut d| d.next().is_none())
                .unwrap_or(true);

        if needs_download {
            let url = config.external_ui_url.as_deref();
            info!("UI directory empty, downloading metacubexd...");
            match ui::download_ui(&ui_dir, url).await {
                Ok(()) => info!("UI downloaded to {}", ui_dir.display()),
                Err(e) => warn!(
                    "Failed to download UI: {} (dashboard will be unavailable)",
                    e
                ),
            }
        }
    }

    let mut app = Router::new()
        // Root — mihomo serves version at both / and /version
        .route("/", get(version::get_version))
        .route("/version", get(version::get_version))
        // System
        .route("/memory", get(version::get_memory))
        .route("/traffic", get(traffic::get_traffic))
        .route("/logs", get(logs::get_logs))
        // Restart / upgrade
        .route("/restart", post(version::post_restart))
        .route("/upgrade", post(version::post_upgrade_stub))
        .route("/upgrade/ui", post(ui::post_upgrade_ui))
        .route("/upgrade/geo", post(configs::post_configs_geo))
        // Debug
        .route("/debug/gc", put(version::put_debug_gc))
        // Configs
        .route(
            "/configs",
            get(configs::get_configs)
                .put(configs::put_configs)
                .patch(configs::patch_configs),
        )
        .route("/configs/geo", post(configs::post_configs_geo))
        // Proxies
        .route("/proxies", get(proxies::get_proxies))
        .route(
            "/proxies/{name}",
            get(proxies::get_proxy)
                .put(proxies::put_proxy)
                .delete(proxies::delete_proxy),
        )
        .route("/proxies/{name}/delay", get(proxies::get_proxy_delay))
        // Groups — mihomo uses /group (singular), OpenClash also hits /groups
        .route("/group", get(proxies::get_groups))
        .route("/groups", get(proxies::get_groups))
        .route("/group/{name}", get(proxies::get_group))
        .route("/groups/{name}", get(proxies::get_group))
        .route("/group/{name}/delay", get(proxies::get_group_delay))
        .route("/groups/{name}/delay", get(proxies::get_group_delay))
        // Proxy providers
        .route("/providers/proxies", get(proxies::get_providers))
        .route(
            "/providers/proxies/{name}",
            get(proxies::get_provider).put(proxies::put_provider),
        )
        .route(
            "/providers/proxies/{name}/healthcheck",
            get(proxies::get_provider_healthcheck),
        )
        .route(
            "/providers/proxies/{provider}/{name}",
            get(proxies::get_provider_proxy),
        )
        .route(
            "/providers/proxies/{provider}/{name}/healthcheck",
            get(proxies::get_provider_proxy_healthcheck),
        )
        // Rule providers
        .route("/providers/rules", get(rules_api::get_rule_providers))
        .route("/providers/rules/{name}", put(rules_api::put_rule_provider))
        // Rules
        .route("/rules", get(rules_api::get_rules))
        .route("/rules/disable", patch(rules_api::patch_rules_disable))
        // Connections
        .route(
            "/connections",
            get(connections::get_connections).delete(connections::delete_connections),
        )
        .route("/connections/{id}", delete(connections::delete_connection))
        // DNS
        .route("/dns/query", get(dns_api::get_dns_query))
        .route("/dns/flush", post(dns_api::post_dns_flush))
        .route("/dns/fakeip/flush", post(dns_api::post_fakeip_flush))
        // Cache
        .route("/cache/fakeip/flush", post(dns_api::post_fakeip_flush))
        .route("/cache/dns/flush", post(dns_api::post_dns_flush));

    // Serve external UI as static files at /ui/
    if let Some(ui_dir) = ui::resolve_ui_dir(&config) {
        if ui_dir.exists() {
            info!("Serving UI from {} at /ui/", ui_dir.display());
            app = app.nest_service("/ui", ServeDir::new(&ui_dir));
        }
    }

    let app = app
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            secret.unwrap_or_default(),
            auth::auth_middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("API server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
