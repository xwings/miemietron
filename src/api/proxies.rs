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
    expected: Option<String>,
}

/// Parse mihomo-style expected status ranges (e.g. "200" or "200-299" or "200-299/400-499").
/// Parse mihomo-style expected status ranges.
/// mihomo compat: ranges.go supports both `/` and `,` as separators.
fn parse_expected_status(s: &str) -> Option<Vec<(u16, u16)>> {
    if s.is_empty() || s == "*" {
        return None;
    }
    let mut ranges = Vec::new();
    // mihomo compat: `strings.ReplaceAll(expected, ",", "/")` (ranges.go:25)
    let normalized = s.replace(',', "/");
    for part in normalized.split('/') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                ranges.push((lo, hi));
            }
        } else if let Ok(v) = part.parse::<u16>() {
            ranges.push((v, v));
        }
    }
    if ranges.is_empty() { None } else { Some(ranges) }
}

fn status_matches(code: u16, ranges: &[(u16, u16)]) -> bool {
    ranges.iter().any(|&(lo, hi)| code >= lo && code <= hi)
}

/// Perform a delay test through a proxy, matching mihomo's adapter.go URLTest().
///
/// mihomo uses Go's http.Client with DialContext overridden to route through the
/// proxy connection. It sends HTTP HEAD, reads the full HTTP response (handling
/// TLS for HTTPS URLs), and checks the status code against `expected`.
async fn do_delay_test(
    handler: &std::sync::Arc<dyn crate::proxy::OutboundHandler>,
    dns: &std::sync::Arc<crate::dns::DnsResolver>,
    url_str: &str,
    expected_status: Option<&[(u16, u16)]>,
) -> Result<(u16, u16), anyhow::Error> {
    let parsed: url::Url = url_str.parse()?;
    let host = parsed.host_str().unwrap_or("www.gstatic.com").to_string();
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let path = if parsed.query().is_some() {
        format!("{}?{}", parsed.path(), parsed.query().unwrap())
    } else {
        parsed.path().to_string()
    };
    let is_https = parsed.scheme() == "https";

    let target = crate::common::addr::Address::domain(&host, port);
    let start = Instant::now();

    // mihomo compat: connect through proxy, then use full HTTP client (handles TLS)
    let stream = handler.connect_stream(&target, dns).await?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // For HTTPS: wrap with TLS to the destination (the proxy tunnel is already established)
    let status_code = if is_https {
        let provider = rustls::crypto::ring::default_provider();
        let tls_connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_safe_default_protocol_versions()
                .expect("tls config")
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(
                    crate::transport::tls::NoVerifier::new(),
                ))
                .with_no_client_auth(),
        ));
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap());
        let mut tls_stream = tls_connector.connect(server_name, stream).await?;

        let req = format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls_stream.write_all(req.as_bytes()).await?;

        let mut buf = [0u8; 512];
        let n = tls_stream.read(&mut buf).await?;
        parse_http_status(&buf[..n])
    } else {
        let mut stream = stream;
        let req = format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;

        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        parse_http_status(&buf[..n])
    };

    let delay = start.elapsed().as_millis() as u16;

    let status_code = status_code.ok_or_else(|| anyhow::anyhow!("invalid HTTP response"))?;

    // mihomo compat: check expected status (satisfied flag)
    if let Some(ranges) = expected_status {
        if !status_matches(status_code, ranges) {
            return Err(anyhow::anyhow!("expected status {}, got {}",
                ranges.iter().map(|(a,b)| if a == b { format!("{a}") } else { format!("{a}-{b}") }).collect::<Vec<_>>().join("/"),
                status_code));
        }
    }

    Ok((delay, status_code))
}

/// Parse HTTP status code from response bytes.
fn parse_http_status(buf: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(buf).ok()?;
    // "HTTP/1.1 204 No Content"
    if !s.starts_with("HTTP/") {
        return None;
    }
    let status_part = s.get(9..12)?;
    status_part.trim().parse().ok()
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
    let expected_status = query.expected.as_deref().and_then(parse_expected_status);

    let pm = state.app.proxy_manager();
    let handler = pm.get(&name).or_else(|| pm.resolve(&name));
    let handler = match handler {
        Some(h) => h,
        None => return (StatusCode::NOT_FOUND, Json(json!({"message": "proxy not found"}))),
    };

    let dns = state.app.dns_resolver();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    let result = tokio::time::timeout(
        timeout,
        do_delay_test(&handler, &dns, url_str, expected_status.as_deref()),
    )
    .await;

    let store = state.app.proxy_state_store();
    match result {
        Ok(Ok((delay, _status))) => {
            store.record_result(&name, url_str, Some(delay));
            (StatusCode::OK, Json(json!({ "delay": delay })))
        }
        Ok(Err(e)) => {
            store.record_result(&name, url_str, None);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"message": e.to_string()})),
            )
        }
        Err(_) => {
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
    let expected_status = query.expected.as_deref().and_then(parse_expected_status);

    let dns = state.app.dns_resolver();

    // mihomo compat: test all proxies concurrently (groupbase.go URLTest)
    let mut handles = Vec::new();
    for proxy_name in proxy_names {
        let handler = match pm.get(&proxy_name) {
            Some(h) => h,
            None => continue,
        };
        let dns = dns.clone();
        let pname = proxy_name.clone();
        let url = url_str.to_string();
        let expected = expected_status.clone();
        handles.push(tokio::spawn(async move {
            let result = tokio::time::timeout(
                timeout,
                do_delay_test(&handler, &dns, &url, expected.as_deref()),
            )
            .await;

            match result {
                Ok(Ok((delay, _))) => (pname, Some(delay)),
                _ => (pname, None),
            }
        }));
    }

    let store = state.app.proxy_state_store();
    let mut result = serde_json::Map::new();
    for h in handles {
        if let Ok((pname, delay_opt)) = h.await {
            match delay_opt {
                Some(delay) => {
                    store.record_result(&pname, url_str, Some(delay));
                    // mihomo compat: only successful proxies appear in the map
                    result.insert(pname, json!(delay));
                }
                None => {
                    store.record_result(&pname, url_str, None);
                    // mihomo compat: failed proxies are NOT included in the response
                }
            }
        }
    }

    // mihomo compat: returns 504 if all proxies timeout (groupbase.go:252-256)
    if result.is_empty() {
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
