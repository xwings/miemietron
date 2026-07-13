use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
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

/// mihomo compat: constant/adapters.go DefaultTestURL
const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

/// Group config fields needed by `group_json`.
struct GroupConfigFields {
    /// Raw `url:` from config (per-type blanking/defaulting happens in
    /// `group_json`).
    url: Option<String>,
    hidden: bool,
    icon: String,
    disable_udp: bool,
    /// mihomo compat: parser.go:123-127 — expected-status is trimmed and
    /// normalized to "*" when unset/empty.
    expected_status: String,
    /// mihomo compat: parser.go:74-76 — empty-fallback defaults to COMPATIBLE.
    empty_fallback: String,
}

fn group_config_fields(state: &ApiState, name: &str) -> GroupConfigFields {
    let config = state.app.config();
    if let Some(g) = config.proxy_groups.iter().find(|g| g.name == name) {
        let expected_status = g
            .expected_status
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
            .to_string();
        let empty_fallback = g
            .extra
            .get("empty-fallback")
            .and_then(|v| v.as_str())
            .unwrap_or("COMPATIBLE")
            .to_string();
        GroupConfigFields {
            url: g.url.clone(),
            hidden: g.hidden.unwrap_or(false),
            icon: g.icon.clone().unwrap_or_default(),
            disable_udp: g.disable_udp.unwrap_or(false),
            expected_status,
            empty_fallback,
        }
    } else {
        GroupConfigFields {
            url: None,
            hidden: false,
            icon: String::new(),
            disable_udp: false,
            expected_status: "*".to_string(),
            empty_fallback: "COMPATIBLE".to_string(),
        }
    }
}

/// Build the full JSON object for a proxy group, matching the fields mihomo's
/// group MarshalJSON + adapter.Proxy wrapper emit that dashboards read.
///
/// mihomo compat, per group type:
/// - Selector (selector.go:52-73): `now` + `testUrl` blanked when it equals
///   DefaultTestURL (so the dashboard follows its own settings); NO
///   `expectedStatus` / `fixed` keys.
/// - URLTest (urltest.go:169-185) / Fallback (fallback.go:79-95): `now`,
///   `testUrl` as configured (not blanked), `expectedStatus` and `fixed`
///   (the force-pinned name).
/// - LoadBalance (loadbalance.go:225-239): NO `now` key, `testUrl`,
///   `expectedStatus`.
fn group_json(state: &ApiState, name: &str, group: &dyn crate::proxy_group::ProxyGroup) -> Value {
    let cfg = group_config_fields(state, name);
    let gtype = group.group_type();

    // mihomo compat: SupportUDP — selector.go:38-44 / urltest.go:156-161 /
    // fallback.go:64-71 resolve the active member's SupportUDP (recursively
    // through nested groups); loadbalance.go:123-125 is just !disableUDP.
    let udp = if cfg.disable_udp {
        false
    } else if gtype == "LoadBalance" {
        true
    } else {
        state
            .app
            .proxy_manager()
            .resolve(name)
            .map(|h| h.supports_udp())
            .unwrap_or(false)
    };

    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), json!(name));
    obj.insert("type".to_string(), json!(gtype));
    obj.insert("udp".to_string(), json!(udp));
    obj.insert("history".to_string(), json!(proxy_history(state, name)));
    obj.insert("extra".to_string(), proxy_extra(state, name));
    obj.insert("all".to_string(), json!(group.all()));
    obj.insert("alive".to_string(), json!(proxy_alive(state, name)));
    obj.insert("hidden".to_string(), json!(cfg.hidden));
    obj.insert("icon".to_string(), json!(cfg.icon));
    obj.insert("emptyFallback".to_string(), json!(cfg.empty_fallback));

    match gtype {
        "LoadBalance" => {
            obj.insert(
                "testUrl".to_string(),
                json!(cfg.url.as_deref().unwrap_or(DEFAULT_TEST_URL)),
            );
            obj.insert("expectedStatus".to_string(), json!(cfg.expected_status));
        }
        "URLTest" | "Fallback" => {
            obj.insert("now".to_string(), json!(group.now()));
            obj.insert(
                "testUrl".to_string(),
                json!(cfg.url.as_deref().unwrap_or(DEFAULT_TEST_URL)),
            );
            obj.insert("expectedStatus".to_string(), json!(cfg.expected_status));
            obj.insert("fixed".to_string(), json!(group.fixed()));
        }
        // Selector (and unknown types treated as selector)
        _ => {
            obj.insert("now".to_string(), json!(group.now()));
            let url = match cfg.url.as_deref() {
                None | Some(DEFAULT_TEST_URL) => "",
                Some(u) => u,
            };
            obj.insert("testUrl".to_string(), json!(url));
        }
    }

    Value::Object(obj)
}

/// Build the full JSON object for a single (non-group) proxy, matching mihomo's
/// `adapter.Proxy.MarshalJSON` fields that dashboards read.
fn proxy_json(state: &ApiState, name: &str, proxy_type: &str, udp: bool) -> Value {
    json!({
        "name": name,
        "type": proxy_type,
        "udp": udp,
        "history": proxy_history(state, name),
        "extra": proxy_extra(state, name),
        "alive": proxy_alive(state, name),
    })
}

/// Non-group proxy JSON as emitted under `/proxies`, with the empty
/// `all`/`now` fields dashboards expect for plain proxies.
fn plain_proxy_json(state: &ApiState, name: &str, proxy_type: &str, udp: bool) -> Value {
    json!({
        "name": name,
        "type": proxy_type,
        "udp": udp,
        "history": proxy_history(state, name),
        "all": [],
        "now": "",
        "alive": proxy_alive(state, name),
        "extra": proxy_extra(state, name),
    })
}

/// Group names in config order, then any live groups not in config
/// (shouldn't happen, but be safe).
fn ordered_group_names(
    config: &crate::config::MiemieConfig,
    live_groups: &std::collections::HashMap<
        String,
        std::sync::Arc<dyn crate::proxy_group::ProxyGroup>,
    >,
) -> Vec<String> {
    let mut group_names: Vec<String> = config.proxy_groups.iter().map(|g| g.name.clone()).collect();
    for (name, _) in live_groups.iter() {
        if !group_names.contains(name) {
            group_names.push(name.clone());
        }
    }
    group_names
}

/// Persist current group selections to cache.db when `store-selected` is on.
/// `action` names the operation in the failure log.
fn persist_selections_if_enabled(state: &ApiState, action: &str) {
    let store_selected = state
        .app
        .config()
        .profile
        .as_ref()
        .map(|p| p.store_selected)
        .unwrap_or(false);
    if store_selected {
        let selections = state.app.proxy_manager().get_all_selections();
        let home_dir = &state.app.home_dir;
        if let Err(e) = crate::store::save_selected(home_dir, &selections) {
            tracing::warn!("Failed to persist {}: {}", action, e);
        }
    }
}

pub async fn get_proxies(State(state): State<ApiState>) -> Json<Value> {
    // mihomo compat: ordered map — GLOBAL first, then groups (config order),
    // then DIRECT/REJECT, then individual proxies.
    let mut proxies = serde_json::Map::new();
    let pm = state.app.proxy_manager();

    // Collect group info first (need group_names for GLOBAL)
    let live_groups = pm.list_live_groups();
    let config = state.app.config();
    let group_names = ordered_group_names(&config, live_groups);

    // 1. GLOBAL first — a real live selector (see ProxyManager GLOBAL setup).
    if let Some(global) = live_groups.get("GLOBAL") {
        proxies.insert(
            "GLOBAL".to_string(),
            group_json(&state, "GLOBAL", global.as_ref()),
        );
    }

    // 2. Proxy groups in config order (GLOBAL already emitted above)
    for name in &group_names {
        if name == "GLOBAL" {
            continue;
        }
        if let Some(group) = live_groups.get(name) {
            proxies.insert(name.clone(), group_json(&state, name, group.as_ref()));
        }
    }

    // 3. DIRECT and REJECT
    let all_proxies = pm.list_proxies();
    for p in &all_proxies {
        if p.name == "DIRECT" || p.name == "REJECT" || p.name == "REJECT-DROP" {
            proxies.insert(
                p.name.clone(),
                plain_proxy_json(&state, &p.name, &p.proxy_type, p.udp),
            );
        }
    }

    // 4. Individual proxies
    for p in &all_proxies {
        if p.name == "DIRECT" || p.name == "REJECT" || p.name == "REJECT-DROP" {
            continue;
        }
        proxies.insert(
            p.name.clone(),
            plain_proxy_json(&state, &p.name, &p.proxy_type, p.udp),
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
        return Ok(Json(group_json(&state, &name, group.as_ref())));
    }

    if let Some(handler) = state.app.proxy_manager().get(&name) {
        Ok(Json(plain_proxy_json(
            &state,
            handler.name(),
            handler.proto(),
            handler.supports_udp(),
        )))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct DelayQuery {
    url: Option<String>,
    timeout: Option<String>,
    expected: Option<String>,
}

// mihomo compat: expected-status parsing/matching lives with the groups
// (utils.NewUnsignedRanges / IntRanges.Check ports).
use crate::proxy_group::{parse_expected_status, status_matches};

/// Perform a delay test through a proxy, matching mihomo's adapter.go URLTest().
///
/// mihomo uses Go's http.Client with DialContext overridden to route through the
/// proxy connection. It sends HTTP HEAD and reads the full HTTP response
/// (handling TLS for HTTPS URLs). Returns (delay_ms, status_code); the caller
/// applies expected-status "satisfied" semantics — an unexpected status is NOT
/// an error (adapter.go:166-200).
async fn do_delay_test(
    handler: &std::sync::Arc<dyn crate::proxy::OutboundHandler>,
    dns: &std::sync::Arc<crate::dns::DnsResolver>,
    url_str: &str,
) -> Result<(u16, u16), anyhow::Error> {
    let parsed: url::Url = url_str.parse()?;
    let host = parsed.host_str().unwrap_or("www.gstatic.com").to_string();
    let port = parsed
        .port()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let path = if let Some(query) = parsed.query() {
        format!("{}?{}", parsed.path(), query)
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
        let server_name =
            rustls::pki_types::ServerName::try_from(host.clone()).unwrap_or_else(|_| {
                rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap()
            });
        let mut tls_stream = tls_connector.connect(server_name, stream).await?;

        let req = format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls_stream.write_all(req.as_bytes()).await?;
        // Flush so message-framed transports (WebSocket) actually put the
        // request on the wire — write_all alone leaves it buffered in the sink.
        tls_stream.flush().await?;

        let mut buf = [0u8; 512];
        let n = tls_stream.read(&mut buf).await?;
        parse_http_status(&buf[..n])
    } else {
        let mut stream = stream;
        let req = format!("HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        parse_http_status(&buf[..n])
    };

    let delay = start.elapsed().as_millis() as u16;

    let status_code = status_code.ok_or_else(|| anyhow::anyhow!("invalid HTTP response"))?;

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
    // mihomo compat: proxies.go:108-114 — `timeout` is required and parsed
    // with bitSize 16; missing/invalid returns 400 "Body invalid".
    let timeout_ms = match query.timeout.as_deref().unwrap_or("").parse::<i16>() {
        Ok(t) => t.max(0) as u64,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
        }
    };
    // mihomo compat: proxies.go:116-121 — invalid `expected` returns 400.
    let expected_status = match parse_expected_status(query.expected.as_deref().unwrap_or("")) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
        }
    };

    let pm = state.app.proxy_manager();
    let handler = pm.get(&name).or_else(|| pm.resolve(&name));
    let handler = match handler {
        Some(h) => h,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"message": "Resource not found"})),
            )
        }
    };

    let dns = state.app.dns_resolver();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    let result = tokio::time::timeout(timeout, do_delay_test(&handler, &dns, url_str)).await;

    let store = state.app.proxy_state_store();
    match result {
        Ok(Ok((delay, status))) => {
            let satisfied = expected_status
                .as_deref()
                .is_none_or(|r| status_matches(status, r));
            if satisfied {
                store.record_result(&name, url_str, Some(delay));
            } else {
                // mihomo compat: adapter.go URLTest — an unexpected status is
                // not an error: the default state stays alive with the real
                // delay; only the per-URL extra state goes dead. The API
                // still returns 200 with the delay (proxies.go:135-147).
                store.record_unexpected_status(&name, url_str, delay);
            }
            if delay == 0 {
                // mihomo compat: proxies.go:135 — delay == 0 is a failure.
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"message": "An error occurred in the delay test"})),
                )
            } else {
                (StatusCode::OK, Json(json!({ "delay": delay })))
            }
        }
        Ok(Err(_)) => {
            store.record_result(&name, url_str, None);
            // mihomo compat: proxies.go:135-143 — on error delay is always 0,
            // so the body is the fixed delay-test error message.
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"message": "An error occurred in the delay test"})),
            )
        }
        Err(_) => {
            store.record_result(&name, url_str, None);
            // mihomo compat: proxies.go:129-133 — context deadline exceeded
            // returns 504 "Timeout" (ErrRequestTimeout).
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({"message": "Timeout"})),
            )
        }
    }
}

#[derive(Deserialize)]
pub struct SelectBody {
    name: String,
}

/// mihomo compat: accept JSON body regardless of Content-Type header.
/// Dashboard (ky library) sends body without Content-Type.
pub async fn put_proxy(
    State(state): State<ApiState>,
    Path(group_name): Path<String>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let body: SelectBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
                .into_response()
        }
    };
    let proxy_manager = state.app.proxy_manager();
    let group = match proxy_manager.get_group(&group_name) {
        Some(g) => g,
        None => {
            // mihomo compat: proxies.go:85-90 — a plain proxy (any adapter
            // that is not SelectAble) gets 400 "Must be a Selector"; an
            // unknown name gets 404 from findProxyByName.
            return if proxy_manager.get(&group_name).is_some() {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Must be a Selector"})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"message": "Resource not found"})),
                )
                    .into_response()
            };
        }
    };
    // mihomo compat: LoadBalance has no Set()/ForceSet() — not SelectAble.
    if group.group_type() == "LoadBalance" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Must be a Selector"})),
        )
            .into_response();
    }

    if group.select(&body.name) {
        tracing::info!("Selected proxy '{}' in group '{}'", body.name, group_name);

        // Persist selection if store-selected is enabled
        persist_selections_if_enabled(&state, "proxy selection");

        StatusCode::NO_CONTENT.into_response()
    } else {
        tracing::warn!(
            "Failed to select proxy '{}' in group '{}' (proxy not in group)",
            body.name,
            group_name
        );
        // mihomo compat: proxies.go:92-95 — Set() error is 400 with the
        // selector.go "proxy not exist" wording.
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Selector update error: proxy not exist"})),
        )
            .into_response()
    }
}

pub async fn delete_proxy(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let proxy_manager = state.app.proxy_manager();

    // mihomo compat: proxies.go:150-160 — DELETE /proxies/{name} unfixes only
    // SelectAble non-Selector groups (URLTest, Fallback); Selector,
    // LoadBalance and plain proxies get 400 "Body invalid"; unknown names 404.
    let group = match proxy_manager.get_group(&name) {
        Some(g) => g,
        None => {
            return if proxy_manager.get(&name).is_some() {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Body invalid"})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"message": "Resource not found"})),
                )
                    .into_response()
            };
        }
    };
    if group.group_type() != "URLTest" && group.group_type() != "Fallback" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Body invalid"})),
        )
            .into_response();
    }

    group.clear_selection();
    tracing::info!("Cleared forced selection for group '{}'", name);

    // Persist the reset selection if store-selected is enabled
    persist_selections_if_enabled(&state, "proxy selection reset");

    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_groups(State(state): State<ApiState>) -> Json<Value> {
    // mihomo compat: `groups.go:getGroups` returns `{"proxies": [<group>...]}`
    // as an ARRAY (a `[]C.Proxy`), in tunnel-proxy order. Dashboards iterate it
    // as a list — an object map breaks metacubexd's group page.
    let pm = state.app.proxy_manager();
    let live_groups = pm.list_live_groups();
    let config = state.app.config();

    let group_names = ordered_group_names(&config, live_groups);

    let mut groups: Vec<Value> = Vec::with_capacity(group_names.len());
    for name in &group_names {
        if let Some(group) = live_groups.get(name) {
            groups.push(group_json(&state, name, group.as_ref()));
        }
    }

    Json(json!({ "proxies": groups }))
}

pub async fn get_group(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    if let Some(group) = state.app.proxy_manager().get_group(&name) {
        Ok(Json(group_json(&state, &name, group.as_ref())))
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

    let group = match pm.get_group(&name) {
        Some(g) => g,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"message": "group not found"})),
            )
        }
    };

    // mihomo compat: clear force-pinned selection on non-Selector groups
    // before running group delay test (groups.go:62-65).
    if group.group_type() != "Selector" {
        group.clear_selection();
    }
    let proxy_names = group.all();

    // mihomo compat: groups.go:68-81 — `timeout` is required and parsed with
    // bitSize 32; missing/invalid returns 400 "Body invalid"; so does an
    // invalid `expected`.
    let timeout_ms = match query.timeout.as_deref().unwrap_or("").parse::<i32>() {
        Ok(t) => t.max(0) as u64,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
        }
    };
    let expected_status = match parse_expected_status(query.expected.as_deref().unwrap_or("")) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
        }
    };
    let timeout = std::time::Duration::from_millis(timeout_ms);

    // mihomo compat: urltest.go:195-197 — URLTest.URLTest ignores the passed
    // url and always tests the group's own testUrl, so the results refresh
    // the auto-selection state. Other group types use the query url.
    let url_str = if group.group_type() == "URLTest" {
        state
            .app
            .config()
            .proxy_groups
            .iter()
            .find(|g| g.name == name)
            .and_then(|g| g.url.clone())
            .unwrap_or_else(|| DEFAULT_TEST_URL.to_string())
    } else {
        query
            .url
            .clone()
            .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string())
    };

    let dns = state.app.dns_resolver();

    // mihomo compat: test all proxies concurrently (groupbase.go URLTest)
    let mut handles = Vec::new();
    for proxy_name in proxy_names {
        // mihomo compat: group members can themselves be groups (Proxy.URLTest
        // on a group dials through its current selection). Resolve nested
        // groups to their underlying handler but record under the member name.
        let handler = match pm.get(&proxy_name).or_else(|| pm.resolve(&proxy_name)) {
            Some(h) => h,
            None => continue,
        };
        let dns = dns.clone();
        let pname = proxy_name.clone();
        let url = url_str.clone();
        handles.push(tokio::spawn(async move {
            let result = tokio::time::timeout(timeout, do_delay_test(&handler, &dns, &url)).await;

            match result {
                Ok(Ok((delay, status))) => (pname, Some((delay, status))),
                _ => (pname, None),
            }
        }));
    }

    let store = state.app.proxy_state_store();
    let mut result = serde_json::Map::new();
    for h in handles {
        if let Ok((pname, outcome)) = h.await {
            match outcome {
                Some((delay, status)) => {
                    let satisfied = expected_status
                        .as_deref()
                        .is_none_or(|r| status_matches(status, r));
                    if satisfied {
                        store.record_result(&pname, &url_str, Some(delay));
                    } else {
                        // mihomo compat: adapter.go URLTest — unexpected status
                        // keeps the default state alive with the real delay.
                        store.record_unexpected_status(&pname, &url_str, delay);
                    }
                    // mihomo compat: groupbase.go URLTest — every proxy whose
                    // probe returned without error is included in the map,
                    // even with an unexpected status.
                    result.insert(pname, json!(delay));
                }
                None => {
                    store.record_result(&pname, &url_str, None);
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

/// Build the list of all non-group proxy objects (the members of the reserved
/// `default` provider). mihomo's `default` Compatible provider contains every
/// configured proxy (`config.go:961`, `provider.ReservedName`).
fn all_proxy_objects(state: &ApiState) -> Vec<Value> {
    state
        .app
        .proxy_manager()
        .list_proxies()
        .iter()
        .map(|p| proxy_json(state, &p.name, &p.proxy_type, p.udp))
        .collect()
}

pub async fn get_providers(State(state): State<ApiState>) -> Json<Value> {
    let mut providers = serde_json::Map::new();

    // mihomo compat: the reserved `default` Compatible provider holds every
    // proxy. yacd/metacubexd enumerate all proxies through it, so it must exist
    // with `type: "Proxy"` and a populated `proxies` array (provider.go:35-44).
    providers.insert(
        "default".to_string(),
        json!({
            "name": "default",
            "type": "Proxy",
            "vehicleType": "Compatible",
            "proxies": all_proxy_objects(&state),
        }),
    );

    for (name, config) in state.app.proxy_manager().list_provider_configs().iter() {
        providers.insert(name.clone(), provider_json(&state, name, config));
    }
    Json(json!({ "providers": Value::Object(providers) }))
}

/// Build a proxy-provider JSON object matching mihomo's marshaled shape:
/// `type` is always `"Proxy"`; `vehicleType` reflects the source; `proxies` is
/// the provider's member proxies (provider.go:130-141).
fn provider_json(
    state: &ApiState,
    name: &str,
    config: &crate::config::proxy::ProxyProviderConfig,
) -> Value {
    let members: Vec<Value> = state
        .app
        .proxy_manager()
        .provider_proxy_infos(name)
        .into_iter()
        .map(|p| proxy_json(state, &p.name, &p.proxy_type, p.udp))
        .collect();
    json!({
        "name": name,
        "type": "Proxy",
        "vehicleType": if config.url.is_some() { "HTTP" } else { "File" },
        "updatedAt": "",
        "subscriptionInfo": {},
        "proxies": members,
    })
}

pub async fn get_provider(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    // mihomo compat: the reserved `default` provider is addressable by name.
    if name == "default" {
        return Ok(Json(json!({
            "name": "default",
            "type": "Proxy",
            "vehicleType": "Compatible",
            "proxies": all_proxy_objects(&state),
        })));
    }
    let proxy_manager = state.app.proxy_manager();
    if let Some(config) = proxy_manager.get_provider_config(&name) {
        Ok(Json(provider_json(&state, &name, config)))
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
