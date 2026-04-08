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

/// Get delay history JSON array for a proxy from the state store.
/// Returns `[]` if no history exists. Matches mihomo's `Proxy.DelayHistory()`.
fn proxy_history(state: &ApiState, name: &str) -> Vec<Value> {
    let store = state.app.proxy_state_store();
    store
        .delay_history(name)
        .into_iter()
        .map(|h| {
            json!({
                "time": h.time.to_rfc3339(),
                "delay": h.delay,
            })
        })
        .collect()
}

/// Get the alive state for a proxy from the state store.
/// Returns `true` for untested proxies. Matches mihomo's `Proxy.alive.Load()`.
fn proxy_alive(state: &ApiState, name: &str) -> bool {
    let store = state.app.proxy_state_store();
    // Check default state; untested proxies default to alive (mihomo compat)
    store.alive_for_url(name, "")
}

/// Get extra per-URL delay histories for a proxy.
/// Returns `{}` if no extra state exists. Matches mihomo's `Proxy.ExtraDelayHistories()`.
fn proxy_extra(state: &ApiState, name: &str) -> Value {
    let store = state.app.proxy_state_store();
    let extras = store.extra_delay_histories(name);
    if extras.is_empty() {
        return json!({});
    }
    Value::Object(extras.into_iter().collect())
}

pub async fn get_proxies(State(state): State<ApiState>) -> Json<Value> {
    // mihomo compat: ordered map — GLOBAL first, then groups (config order),
    // then DIRECT/REJECT, then individual proxies.
    let mut proxies = serde_json::Map::new();
    let pm = state.app.proxy_manager();

    // Collect group info first (need group_names for GLOBAL)
    let live_groups = pm.list_live_groups();
    let config = state.app.config();
    // Use config order for groups
    let mut group_names: Vec<String> = config
        .proxy_groups
        .iter()
        .map(|g| g.name.clone())
        .collect();
    // Add any live groups not in config (shouldn't happen, but be safe)
    for (name, _) in live_groups.iter() {
        if !group_names.contains(name) {
            group_names.push(name.clone());
        }
    }

    // 1. GLOBAL first
    let first_group = group_names.first().cloned().unwrap_or_default();
    proxies.insert(
        "GLOBAL".to_string(),
        json!({
            "name": "GLOBAL",
            "type": "Selector",
            "udp": true,
            "history": proxy_history(&state, "GLOBAL"),
            "all": group_names,
            "now": first_group,
            "alive": proxy_alive(&state, "GLOBAL"),
        }),
    );

    // 2. Proxy groups in config order
    for name in &group_names {
        if let Some(group) = live_groups.get(name) {
            proxies.insert(
                name.clone(),
                json!({
                    "name": name,
                    "type": group.group_type(),
                    "udp": true,
                    "history": proxy_history(&state, name),
                    "all": group.all(),
                    "now": group.now(),
                    "alive": proxy_alive(&state, name),
                }),
            );
        }
    }

    // 3. DIRECT and REJECT
    for p in pm.list_proxies() {
        if p.name == "DIRECT" || p.name == "REJECT" || p.name == "REJECT-DROP" {
            proxies.insert(
                p.name.clone(),
                json!({
                    "name": p.name,
                    "type": p.proxy_type,
                    "udp": p.udp,
                    "history": proxy_history(&state, &p.name),
                    "all": [],
                    "now": "",
                    "alive": proxy_alive(&state, &p.name),
                    "extra": proxy_extra(&state, &p.name),
                }),
            );
        }
    }

    // 4. Individual proxies
    for p in pm.list_proxies() {
        if p.name == "DIRECT" || p.name == "REJECT" || p.name == "REJECT-DROP" {
            continue;
        }
        proxies.insert(
            p.name.clone(),
            json!({
                "name": p.name,
                "type": p.proxy_type,
                "udp": p.udp,
                "history": proxy_history(&state, &p.name),
                "all": [],
                "now": "",
                "alive": proxy_alive(&state, &p.name),
                "extra": proxy_extra(&state, &p.name),
            }),
        );
    }

    Json(json!({ "proxies": Value::Object(proxies) }))
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
            "history": proxy_history(&state, &name),
            "all": group.all(),
            "now": group.now(),
            "alive": proxy_alive(&state, &name),
        })));
    }

    if let Some(handler) = state.app.proxy_manager().get(&name) {
        Ok(Json(json!({
            "name": handler.name(),
            "type": handler.proto(),
            "udp": handler.supports_udp(),
            "history": proxy_history(&state, &name),
            "all": [],
            "now": "",
            "alive": proxy_alive(&state, &name),
            "extra": proxy_extra(&state, &name),
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct DelayQuery {
    url: Option<String>,
    timeout: Option<u64>,
    #[allow(dead_code)]
    expected: Option<String>,
}

pub async fn get_proxy_delay(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> (StatusCode, Json<Value>) {
    let url_str = query
        .url
        .as_deref()
        .unwrap_or("http://www.gstatic.com/generate_204");
    let timeout_ms = query.timeout.unwrap_or(5000);

    // Resolve the proxy handler
    let pm = state.app.proxy_manager();
    let handler = pm
        .get(&name)
        .or_else(|| pm.resolve(&name));
    let handler = match handler {
        Some(h) => h,
        None => return (StatusCode::NOT_FOUND, Json(json!({"message": "proxy not found"}))),
    };

    let dns = state.app.dns_resolver();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    // Parse URL to extract host and path
    let parsed: url::Url = match url_str.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"message": "invalid url"}))),
    };
    let host = parsed.host_str().unwrap_or("www.gstatic.com").to_string();
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let path = if parsed.query().is_some() {
        format!("{}?{}", parsed.path(), parsed.query().unwrap())
    } else {
        parsed.path().to_string()
    };

    let target = crate::common::addr::Address::domain(&host, port);

    let start = Instant::now();

    // Connect through the proxy and send an HTTP HEAD request
    // mihomo compat: uses http.Client with DialContext overridden to use proxy connection
    let result = tokio::time::timeout(timeout, async {
        let mut stream = handler.connect_stream(&target, &dns).await?;

        // Send HTTP HEAD
        let req = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(req.as_bytes()).await?;

        // Read response status line
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if response.starts_with("HTTP/") {
            Ok::<_, anyhow::Error>(())
        } else {
            Err(anyhow::anyhow!("invalid HTTP response"))
        }
    })
    .await;

    let delay = start.elapsed().as_millis() as u64;
    let store = state.app.proxy_state_store();
    match result {
        Ok(Ok(())) => {
            // Record successful delay to the state store
            store.record_result(&name, url_str, Some(delay as u16));
            (StatusCode::OK, Json(json!({ "delay": delay })))
        }
        // mihomo compat: returns 503 on error, 504 on timeout
        Ok(Err(e)) => {
            // Record failure
            store.record_result(&name, url_str, None);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"message": e.to_string()})),
            )
        }
        Err(_) => {
            // Record timeout as failure
            store.record_result(&name, url_str, None);
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({"message": "An error occurred in the delay test"})),
            )
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

    // mihomo compat: DELETE /proxies/{name} clears force-pinned selection
    // on non-Selector groups (URLTest, Fallback). Returns 400 for Selector groups.
    if let Some(group) = proxy_manager.get_group(&name) {
        if group.group_type() == "Selector" {
            return StatusCode::BAD_REQUEST;
        }

        group.clear_selection();
        tracing::info!("Cleared forced selection for group '{}'", name);

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

        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

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
                "history": proxy_history(&state, name),
                "all": group.all(),
                "now": group.now(),
                "alive": proxy_alive(&state, name),
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
            "history": proxy_history(&state, &name),
            "all": group.all(),
            "now": group.now(),
            "alive": proxy_alive(&state, &name),
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn get_group_delay(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> (StatusCode, Json<Value>) {
    let pm = state.app.proxy_manager();

    // mihomo compat: clear force-pinned selection on non-Selector groups
    // before running group delay test.
    if let Some(group) = pm.get_group(&name) {
        if group.group_type() != "Selector" {
            group.clear_selection();
        }
    }

    let proxy_names = match pm.group_proxy_names(&name) {
        Some(names) => names,
        None => return (StatusCode::NOT_FOUND, Json(json!({"message": "group not found"}))),
    };

    let url_str = query
        .url
        .as_deref()
        .unwrap_or("http://www.gstatic.com/generate_204");
    let timeout_ms = query.timeout.unwrap_or(5000);
    let timeout = std::time::Duration::from_millis(timeout_ms);

    // Parse URL once
    let parsed: url::Url = match url_str.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"message": "invalid url"}))),
    };
    let host = parsed.host_str().unwrap_or("www.gstatic.com").to_string();
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let path = if parsed.query().is_some() {
        format!("{}?{}", parsed.path(), parsed.query().unwrap())
    } else {
        parsed.path().to_string()
    };

    let dns = state.app.dns_resolver();

    // mihomo compat: test all proxies concurrently through the actual proxy connections
    let mut handles = Vec::new();
    for proxy_name in proxy_names {
        let handler = pm.get(&proxy_name);
        if handler.is_none() {
            continue;
        }
        let handler = handler.unwrap();
        let dns = dns.clone();
        let pname = proxy_name.clone();
        let host = host.clone();
        let path = path.clone();
        handles.push(tokio::spawn(async move {
            let target = crate::common::addr::Address::domain(&host, port);
            let start = Instant::now();

            let result = tokio::time::timeout(timeout, async {
                let mut stream = handler.connect_stream(&target, &dns).await?;
                let req = format!(
                    "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                );
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream.write_all(req.as_bytes()).await?;
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await?;
                let response = String::from_utf8_lossy(&buf[..n]);
                if response.starts_with("HTTP/") {
                    Ok::<_, anyhow::Error>(())
                } else {
                    Err(anyhow::anyhow!("invalid HTTP response"))
                }
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    let delay = start.elapsed().as_millis() as u64;
                    (pname, Some(delay))
                }
                _ => (pname, None),
            }
        }));
    }

    let store = state.app.proxy_state_store();
    let mut result = serde_json::Map::new();
    let mut any_success = false;
    for h in handles {
        if let Ok((pname, delay_opt)) = h.await {
            match delay_opt {
                Some(delay) => {
                    any_success = true;
                    // Record successful delay to the state store
                    store.record_result(&pname, url_str, Some(delay as u16));
                    result.insert(pname, json!(delay));
                }
                None => {
                    // Record failure
                    store.record_result(&pname, url_str, None);
                    result.insert(pname, json!(0));
                }
            }
        }
    }

    // mihomo compat: returns 504 if all proxies timeout
    if !any_success && !result.is_empty() {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({"message": "get delay: all proxies timeout"})),
        );
    }

    (StatusCode::OK, Json(Value::Object(result)))
}

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
                Json(json!({ "message": format!("{}", e) })),
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
