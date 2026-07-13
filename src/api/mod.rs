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

/// Runtime log-level reload hook. Set once at startup from `main` (which owns
/// the tracing reload handle whose concrete type is unnameable here); called by
/// `PATCH /configs {"log-level"}` so the change affects real output.
type LogReloadFn = Box<dyn Fn(&str) + Send + Sync>;
static LOG_RELOAD: std::sync::OnceLock<LogReloadFn> = std::sync::OnceLock::new();

/// Register the log-level reload hook (idempotent; first caller wins).
pub fn set_log_reload_fn(f: LogReloadFn) {
    let _ = LOG_RELOAD.set(f);
}

/// Apply a new log level to the live tracing filter, if a hook is registered.
pub fn reload_log_level(level: &str) {
    if let Some(f) = LOG_RELOAD.get() {
        f(level);
    }
}

/// Mutable runtime configuration that can be changed via PATCH /configs.
pub struct RuntimeConfig {
    pub mode: String,
    pub log_level: String,
    pub allow_lan: Option<bool>,
    pub find_process_mode: Option<String>,
    pub sniffing: Option<bool>,
    pub tcp_concurrent: Option<bool>,
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

/// If `request` carries a WebSocket `Upgrade` header, extract the upgrader
/// (or the rejection converted to a response). `None` means plain HTTP —
/// mihomo's chi handlers serve both on the same route, so several endpoints
/// share this sniff-and-upgrade dance.
pub(crate) async fn websocket_upgrade(
    request: axum::http::Request<axum::body::Body>,
) -> Option<Result<axum::extract::WebSocketUpgrade, axum::response::Response>> {
    use axum::extract::FromRequestParts;
    use axum::response::IntoResponse;

    let is_ws = request
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if !is_ws {
        return None;
    }
    let (mut parts, _body) = request.into_parts();
    Some(
        axum::extract::WebSocketUpgrade::from_request_parts(&mut parts, &())
            .await
            .map_err(IntoResponse::into_response),
    )
}

pub async fn start_server(addr: &str, secret: Option<String>, state: ApiState) -> Result<()> {
    // Bind before the UI download so an unreachable download URL can't block
    // the whole REST API from coming up.
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let app = build_app(secret, state).await;

    info!("API server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

/// Serve the REST API on a unix socket (`external-controller-unix` /
/// `--ext-ctl-unix`).
///
/// mihomo compat: `hub/route/server.go::startUnix` — create the parent
/// directory if missing, unlink a stale socket file before bind, chmod the
/// socket 0666, and serve the router with an EMPTY secret (local socket
/// access is trusted; authentication is skipped).
#[cfg(unix)]
pub async fn start_unix_server(path: &std::path::Path, state: ApiState) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    }

    let app = build_app(None, state).await;

    info!("RESTful API unix listening at: {}", path.display());
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build the API router (shared by the TCP and unix-socket servers).
async fn build_app(secret: Option<String>, state: ApiState) -> Router {
    // mihomo compat: CORS matching chi cors.Options (server.go:80-88) —
    // external-controller-cors.allow-origins restricts origins (default "*");
    // allow_private_network required for Chrome Private Network Access
    // (dashboard → router IP), default true (config.go:588-591).
    let cors_cfg = state.app.config().external_controller_cors.clone();
    let (allow_origins, allow_private) = cors_cfg.map_or((vec![], true), |c| {
        (c.allow_origins, c.allow_private_network)
    });
    let cors = if allow_origins.is_empty() || allow_origins.iter().any(|o| o == "*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_private_network(allow_private)
            .max_age(std::time::Duration::from_secs(300))
    } else {
        let origins: Vec<axum::http::HeaderValue> = allow_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_private_network(allow_private)
            .max_age(std::time::Duration::from_secs(300))
    };

    // Auto-download UI if external-ui is configured but directory is empty/missing.
    // Guarded so the TCP and unix servers (both call build_app concurrently)
    // don't race two downloads into the same directory.
    static UI_DOWNLOAD_STARTED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let config = state.app.config();
    if let Some(ui_dir) = ui::resolve_ui_download_dir(&config)
        .filter(|_| !UI_DOWNLOAD_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst))
    {
        let needs_download = !ui_dir.exists()
            || ui_dir
                .read_dir()
                .map(|mut d| d.next().is_none())
                .unwrap_or(true);

        if needs_download {
            let url = config.external_ui_url.as_deref();
            info!("UI directory empty, downloading dashboard...");
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
        // Root — mihomo returns {"hello": "mihomo"} at /
        .route("/", get(version::get_hello))
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
        .route(
            "/providers/rules/{name}",
            get(rules_api::get_rule_provider).put(rules_api::put_rule_provider),
        )
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

    app.layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            secret.unwrap_or_default(),
            auth::auth_middleware,
        ))
        .with_state(state)
}
