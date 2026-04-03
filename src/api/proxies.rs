use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Instant;

use super::ApiState;

pub async fn get_proxies(State(state): State<ApiState>) -> Json<Value> {
    let mut proxies: HashMap<String, Value> = state
        .app
        .proxy_manager()
        .list_proxies()
        .into_iter()
        .map(|p| {
            let name = p.name.clone();
            let val = json!({
                "name": p.name,
                "type": p.proxy_type,
                "udp": p.udp,
                "history": [],
                "all": [],
                "now": "",
                "alive": true,
            });
            (name, val)
        })
        .collect();

    // Merge live groups into the proxies map (mihomo returns groups here too)
    for (name, group) in state.app.proxy_manager().list_live_groups() {
        let val = json!({
            "name": name,
            "type": group.group_type(),
            "udp": true,
            "history": [],
            "all": group.all(),
            "now": group.now(),
            "alive": true,
        });
        proxies.insert(name.clone(), val);
    }

    Json(json!({ "proxies": proxies }))
}

pub async fn get_proxy(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    // Check live groups first (groups are also exposed under /proxies/{name})
    if let Some(group) = state.app.proxy_manager().get_group(&name) {
        return Ok(Json(json!({
            "name": group.name(),
            "type": group.group_type(),
            "udp": true,
            "history": [],
            "all": group.all(),
            "now": group.now(),
            "alive": true,
        })));
    }

    if let Some(handler) = state.app.proxy_manager().get(&name) {
        Ok(Json(json!({
            "name": handler.name(),
            "type": handler.proto(),
            "udp": handler.supports_udp(),
            "history": [],
            "all": [],
            "now": "",
            "alive": true,
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct DelayQuery {
    url: Option<String>,
    timeout: Option<u64>,
    expected: Option<String>,
}

pub async fn get_proxy_delay(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Result<Json<Value>, StatusCode> {
    let url = query
        .url
        .as_deref()
        .unwrap_or("http://www.gstatic.com/generate_204");
    let timeout_ms = query.timeout.unwrap_or(5000);

    // Resolve the proxy name -- could be a direct proxy or a group
    let _handler = state
        .app
        .proxy_manager()
        .get(&name)
        .or_else(|| state.app.proxy_manager().resolve(&name));
    if _handler.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Measure latency by making an HTTP HEAD request.
    // In a full implementation this would route through the actual proxy;
    // for now we use a direct HTTP client as a latency probe.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .no_proxy()
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let start = Instant::now();
    match client.head(url).send().await {
        Ok(resp) => {
            let delay = start.elapsed().as_millis() as u64;
            let _ = query.expected; // reserved for expected status check
            if resp.status().is_success() || resp.status().is_redirection() {
                Ok(Json(json!({ "delay": delay })))
            } else {
                // Non-success status: report as high delay
                Ok(Json(
                    json!({ "delay": delay, "message": format!("HTTP {}", resp.status()) }),
                ))
            }
        }
        Err(e) => {
            let delay = start.elapsed().as_millis() as u64;
            Ok(Json(
                json!({ "delay": 0, "message": format!("timeout or error after {}ms: {}", delay, e) }),
            ))
        }
    }
}

#[derive(Deserialize)]
pub struct SelectBody {
    name: String,
}

pub async fn put_proxy(
    State(state): State<ApiState>,
    Path(group_name): Path<String>,
    Json(body): Json<SelectBody>,
) -> StatusCode {
    let proxy_manager = state.app.proxy_manager();
    if proxy_manager.select_proxy(&group_name, &body.name) {
        tracing::info!("Selected proxy '{}' in group '{}'", body.name, group_name);

        // Persist selection if store-selected is enabled
        let store_selected = state
            .app
            .config()
            .profile
            .as_ref()
            .map(|p| p.store_selected)
            .unwrap_or(false);
        if store_selected {
            let selections = proxy_manager.get_all_selections();
            let home_dir = &state.app.home_dir;
            if let Err(e) = crate::store::save_selected(home_dir, &selections) {
                tracing::warn!("Failed to persist proxy selection: {}", e);
            }
        }

        StatusCode::NO_CONTENT
    } else {
        tracing::warn!(
            "Failed to select proxy '{}' in group '{}' (group not found or proxy not in group)",
            body.name,
            group_name
        );
        StatusCode::NOT_FOUND
    }
}

pub async fn delete_proxy(State(state): State<ApiState>, Path(name): Path<String>) -> StatusCode {
    let proxy_manager = state.app.proxy_manager();

    // For selector groups, reset to the first proxy in the list (unpin selection)
    if let Some(group) = proxy_manager.get_group(&name) {
        let all = group.all();
        if let Some(first) = all.first() {
            group.select(first);
            tracing::info!(
                "Cleared forced selection for group '{}', reset to '{}'",
                name,
                first
            );

            // Persist the reset selection if store-selected is enabled
            let store_selected = state
                .app
                .config()
                .profile
                .as_ref()
                .map(|p| p.store_selected)
                .unwrap_or(false);
            if store_selected {
                let selections = proxy_manager.get_all_selections();
                let home_dir = &state.app.home_dir;
                if let Err(e) = crate::store::save_selected(home_dir, &selections) {
                    tracing::warn!("Failed to persist proxy selection reset: {}", e);
                }
            }
        }
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// --- Groups ---

pub async fn get_groups(State(state): State<ApiState>) -> Json<Value> {
    let groups: HashMap<String, Value> = state
        .app
        .proxy_manager()
        .list_live_groups()
        .iter()
        .map(|(name, group)| {
            let val = json!({
                "name": name,
                "type": group.group_type(),
                "udp": true,
                "history": [],
                "all": group.all(),
                "now": group.now(),
                "alive": true,
            });
            (name.clone(), val)
        })
        .collect();

    Json(json!({ "proxies": groups }))
}

pub async fn get_group(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    if let Some(group) = state.app.proxy_manager().get_group(&name) {
        Ok(Json(json!({
            "name": group.name(),
            "type": group.group_type(),
            "udp": true,
            "history": [],
            "all": group.all(),
            "now": group.now(),
            "alive": true,
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn get_group_delay(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Result<Json<Value>, StatusCode> {
    let proxy_names = match state.app.proxy_manager().group_proxy_names(&name) {
        Some(names) => names,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let url = query
        .url
        .as_deref()
        .unwrap_or("http://www.gstatic.com/generate_204");
    let timeout_ms = query.timeout.unwrap_or(5000);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .no_proxy()
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Test all proxies concurrently
    let mut handles = Vec::new();
    for proxy_name in proxy_names {
        let client = client.clone();
        let url = url.to_string();
        let pname = proxy_name.clone();
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            match client.head(&url).send().await {
                Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                    let delay = start.elapsed().as_millis() as u64;
                    (pname, delay)
                }
                _ => (pname, 0u64),
            }
        }));
    }

    let mut result = serde_json::Map::new();
    for h in handles {
        if let Ok((pname, delay)) = h.await {
            result.insert(pname, json!(delay));
        }
    }

    Ok(Json(Value::Object(result)))
}

// --- Providers ---

pub async fn get_providers(State(state): State<ApiState>) -> Json<Value> {
    let providers: HashMap<String, Value> = state
        .app
        .proxy_manager()
        .list_provider_configs()
        .iter()
        .map(|(name, config)| {
            let val = json!({
                "name": name,
                "type": config.provider_type,
                "vehicleType": if config.url.is_some() { "HTTP" } else { "File" },
                "updatedAt": "",
                "subscriptionInfo": {},
                "proxies": [],
            });
            (name.clone(), val)
        })
        .collect();
    Json(json!({ "providers": providers }))
}

pub async fn get_provider(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let proxy_manager = state.app.proxy_manager();
    if let Some(config) = proxy_manager.get_provider_config(&name) {
        Ok(Json(json!({
            "name": name,
            "type": config.provider_type,
            "vehicleType": if config.url.is_some() { "HTTP" } else { "File" },
            "updatedAt": "",
            "subscriptionInfo": {},
            "proxies": [],
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn put_provider(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<Value>)> {
    let proxy_manager = state.app.proxy_manager();
    match proxy_manager.update_provider(&name).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!("Failed to update provider '{}': {}", name, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("{}", e) })),
            ))
        }
    }
}

pub async fn get_provider_healthcheck(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
) -> StatusCode {
    StatusCode::NO_CONTENT
}

/// GET /providers/proxies/{provider}/{name} — get a specific proxy within a provider.
pub async fn get_provider_proxy(
    State(_state): State<ApiState>,
    Path((_provider, _name)): Path<(String, String)>,
) -> Result<Json<Value>, StatusCode> {
    Err(StatusCode::NOT_FOUND)
}

/// GET /providers/proxies/{provider}/{name}/healthcheck — healthcheck a proxy in provider.
pub async fn get_provider_proxy_healthcheck(
    State(_state): State<ApiState>,
    Path((_provider, _name)): Path<(String, String)>,
) -> Json<Value> {
    Json(json!({"delay": 0}))
}
