use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{error, info};

use super::ApiState;

pub async fn get_configs(State(state): State<ApiState>) -> Json<Value> {
    let config = state.app.config();
    let rt = state.app.runtime_config.read();

    // mihomo compat: build geox-url object from config or defaults
    let geox_url = {
        let empty = std::collections::HashMap::new();
        let map = config.geox_url.as_ref().unwrap_or(&empty);
        json!({
            "geoip": map.get("geoip").cloned().unwrap_or_default(),
            "mmdb": map.get("mmdb").cloned().unwrap_or_default(),
            "asn": map.get("asn").cloned().unwrap_or_default(),
            "geosite": map.get("geosite").cloned().unwrap_or_default(),
        })
    };

    Json(json!({
        "port": config.port,
        "socks-port": config.socks_port,
        "redir-port": config.redir_port,
        "tproxy-port": config.tproxy_port,
        "mixed-port": config.mixed_port,
        "allow-lan": rt.allow_lan.unwrap_or(config.allow_lan),
        "bind-address": config.bind_address,
        "mode": rt.mode,
        "log-level": rt.log_level,
        "ipv6": config.ipv6,
        "unified-delay": config.unified_delay,
        "routing-mark": config.routing_mark.unwrap_or(0),
        "tun": {
            "enable": config.tun.enable,
            "device": config.tun.device,
            "stack": config.tun.stack,
            "dns-hijack": config.tun.dns_hijack,
            "auto-route": config.tun.auto_route,
            "auto-detect-interface": config.tun.auto_detect_interface,
            "mtu": config.tun.mtu,
        },
        "interface-name": config.interface_name,
        "geodata-mode": config.geodata_mode,
        "geox-url": geox_url,
        "geo-auto-update": config.geo_auto_update,
        "geo-update-interval": config.geo_update_interval.unwrap_or(24),
        "tcp-concurrent": rt.tcp_concurrent.unwrap_or(config.tcp_concurrent),
        "find-process-mode": rt.find_process_mode.as_deref()
            .unwrap_or(config.find_process_mode.as_deref().unwrap_or("off")),
        "sniffing": rt.sniffing.unwrap_or(
            config.sniffer.as_ref().map(|s| s.enable).unwrap_or(false)
        ),
    }))
}

#[derive(Deserialize, Default)]
pub struct PutConfigsQuery {
    force: Option<bool>,
}

/// PUT /configs — full config reload.
///
/// Accepts JSON body with either:
///   - `{"path": "/path/to/config.yaml"}` — read and reload from that file
///   - `{"payload": "yaml string"}` — parse and reload from the inline YAML
///
/// Supports `?force=true` query param to force reload even if config hasn't changed.
pub async fn put_configs(
    State(state): State<ApiState>,
    Query(query): Query<PutConfigsQuery>,
    Json(body): Json<Value>,
) -> Response {
    let force = query.force.unwrap_or(false);

    let result = if let Some(path_str) = body.get("path").and_then(|v| v.as_str()) {
        // Reload from file path
        let path = std::path::PathBuf::from(path_str);
        if !path.exists() {
            error!("PUT /configs: path does not exist: {}", path.display());
            // mihomo returns a JSON error body; OpenClash treats any non-empty
            // response as failure, so an empty body would mask this.
            return config_error(
                StatusCode::BAD_REQUEST,
                &format!("config path not found: {}", path.display()),
            );
        }
        info!(
            "PUT /configs: reloading from path: {} (force={})",
            path.display(),
            force
        );
        // Update the stored config path so future SIGHUP reloads use it too
        *state.app.config_path.write() = path.clone();
        state.app.reload_from_path(&path).await
    } else if let Some(payload) = body.get("payload").and_then(|v| v.as_str()) {
        // Reload from inline YAML payload
        info!(
            "PUT /configs: reloading from payload ({} bytes, force={})",
            payload.len(),
            force
        );
        state.app.reload_from_str(payload).await
    } else {
        // No path or payload — try reloading from the current config path
        let path = state.app.config_path.read().clone();
        info!(
            "PUT /configs: reloading from current path: {} (force={})",
            path.display(),
            force
        );
        state.app.reload_from_path(&path).await
    };

    match result {
        Ok(()) => {
            info!("PUT /configs: reload successful");
            // mihomo compat: 204 with an EMPTY body. OpenClash's live-config
            // reload (`PUT /configs?force=true`) treats any non-empty response
            // as "Switch Failed".
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!("PUT /configs: reload failed: {}", e);
            config_error(StatusCode::BAD_REQUEST, &e.to_string())
        }
    }
}

/// Build a mihomo-style JSON error response (`{"message": "..."}`) so callers
/// like OpenClash that inspect the body see a real failure instead of an empty
/// success.
fn config_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "message": message }))).into_response()
}

pub async fn patch_configs(State(state): State<ApiState>, Json(body): Json<Value>) -> Response {
    let mut changed = false;

    if let Some(mode) = body.get("mode").and_then(|v| v.as_str()) {
        // mihomo compat: reject invalid modes (tunnel/mode.go errors); OpenClash
        // inspects the response body, so a silent 204 would hide the error.
        if !matches!(mode, "rule" | "global" | "direct") {
            return config_error(
                StatusCode::BAD_REQUEST,
                &format!("invalid mode: {mode}"),
            );
        }
        let mut rt = state.app.runtime_config.write();
        if rt.mode != mode {
            info!("Tunnel mode changed: {} -> {}", rt.mode, mode);
            rt.mode = mode.to_string();
            changed = true;
        }
    }

    if let Some(level) = body.get("log-level").and_then(|v| v.as_str()) {
        if !matches!(
            level,
            "trace" | "debug" | "info" | "warning" | "warn" | "error" | "silent"
        ) {
            return config_error(
                StatusCode::BAD_REQUEST,
                &format!("invalid log-level: {level}"),
            );
        }
        let mut rt = state.app.runtime_config.write();
        if rt.log_level != level {
            info!("Log level changed: {} -> {}", rt.log_level, level);
            rt.log_level = level.to_string();
            drop(rt);
            // Apply to the live tracing filter so output actually changes.
            super::reload_log_level(level);
            changed = true;
        }
    }

    // mihomo compat: PATCH /configs supports allow-lan, sniffing,
    // tcp-concurrent, find-process-mode toggles
    if let Some(allow_lan) = body.get("allow-lan").and_then(|v| v.as_bool()) {
        let mut rt = state.app.runtime_config.write();
        info!("allow-lan changed to {}", allow_lan);
        rt.allow_lan = Some(allow_lan);
        changed = true;
    }

    if let Some(sniffing) = body.get("sniffing").and_then(|v| v.as_bool()) {
        let mut rt = state.app.runtime_config.write();
        info!("sniffing changed to {}", sniffing);
        rt.sniffing = Some(sniffing);
        changed = true;
    }

    if let Some(tcp_concurrent) = body.get("tcp-concurrent").and_then(|v| v.as_bool()) {
        let mut rt = state.app.runtime_config.write();
        info!("tcp-concurrent changed to {}", tcp_concurrent);
        rt.tcp_concurrent = Some(tcp_concurrent);
        changed = true;
    }

    if let Some(fpm) = body.get("find-process-mode").and_then(|v| v.as_str()) {
        let mut rt = state.app.runtime_config.write();
        info!("find-process-mode changed to {}", fpm);
        rt.find_process_mode = Some(fpm.to_string());
        changed = true;
    }

    if let Some(ipv6) = body.get("ipv6").and_then(|v| v.as_bool()) {
        info!("ipv6 changed to {}", ipv6);
        changed = true;
    }

    if let Some(iface) = body.get("interface-name").and_then(|v| v.as_str()) {
        info!("interface-name changed to {}", iface);
        changed = true;
    }

    if changed {
        info!("Config patched successfully");
    }

    StatusCode::NO_CONTENT.into_response()
}

pub async fn post_configs_geo(State(_state): State<ApiState>) -> StatusCode {
    // TODO: update geodata files
    StatusCode::NO_CONTENT
}
