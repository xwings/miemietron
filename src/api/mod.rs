pub mod auth;
pub mod configs;
pub mod connections;
pub mod dns_api;
pub mod logs;
pub mod proxies;
pub mod rules_api;
pub mod version;

use anyhow::Result;
use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::config::MiemieConfig;
use crate::conn::{ConnectionManager, StatsManager};
use crate::dns::DnsResolver;
use crate::proxy::ProxyManager;
use crate::rules::RuleEngine;

/// Shared state for all API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<MiemieConfig>,
    pub proxy_manager: Arc<ProxyManager>,
    pub rule_engine: Arc<RuleEngine>,
    pub conn_manager: Arc<ConnectionManager>,
    pub stats: Arc<StatsManager>,
    pub dns_resolver: Arc<DnsResolver>,
}

pub async fn start_server(addr: &str, secret: Option<String>, state: ApiState) -> Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Version / system
        .route("/version", get(version::get_version))
        .route("/memory", get(version::get_memory))
        .route("/gc", get(version::get_gc))
        .route("/restart", post(version::post_restart))
        // Configs
        .route("/configs", get(configs::get_configs))
        .route("/configs", put(configs::put_configs))
        .route("/configs", patch(configs::patch_configs))
        .route("/configs/geo", post(configs::post_configs_geo))
        // Proxies
        .route("/proxies", get(proxies::get_proxies))
        .route("/proxies/{name}", get(proxies::get_proxy))
        .route("/proxies/{name}", put(proxies::put_proxy))
        .route("/proxies/{name}", delete(proxies::delete_proxy))
        .route("/proxies/{name}/delay", get(proxies::get_proxy_delay))
        // Groups — OpenClash uses both /group and /groups
        .route("/group", get(proxies::get_groups))
        .route("/groups", get(proxies::get_groups))
        .route("/groups/{name}", get(proxies::get_group))
        .route("/groups/{name}/delay", get(proxies::get_group_delay))
        // Providers
        .route("/providers/proxies", get(proxies::get_providers))
        .route("/providers/proxies/{name}", get(proxies::get_provider))
        .route("/providers/proxies/{name}", put(proxies::put_provider))
        .route(
            "/providers/proxies/{name}/healthcheck",
            get(proxies::get_provider_healthcheck),
        )
        .route("/providers/rules", get(rules_api::get_rule_providers))
        .route("/providers/rules/{name}", put(rules_api::put_rule_provider))
        // Rules
        .route("/rules", get(rules_api::get_rules))
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
        .route("/cache/dns/flush", post(dns_api::post_dns_flush))
        // Logs
        .route("/logs", get(logs::get_logs))
        // Middleware
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
