use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{error, info};

use super::ApiState;

pub async fn get_configs(State(state): State<ApiState>) -> Json<Value> {
    let config = state.app.config();
    let rt = state.app.runtime_config.read();
    Json(json!({
        "port": config.port,
        "socks-port": config.socks_port,
        "redir-port": config.redir_port,
        "tproxy-port": config.tproxy_port,
        "mixed-port": config.mixed_port,
        "allow-lan": config.allow_lan,
        "bind-address": config.bind_address,
        "mode": rt.mode,
        "log-level": rt.log_level,
        "ipv6": config.ipv6,
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
        "tcp-concurrent": config.tcp_concurrent,
        "find-process-mode": config.find_process_mode,
        "sniff": config.sniffer.as_ref().map(|s| s.enable).unwrap_or(false),
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
) -> StatusCode {
    let force = query.force.unwrap_or(false);

    let result = if let Some(path_str) = body.get("path").and_then(|v| v.as_str()) {
        // Reload from file path
        let path = std::path::PathBuf::from(path_str);
        if !path.exists() {
            error!("PUT /configs: path does not exist: {}", path.display());
            return StatusCode::BAD_REQUEST;
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
            StatusCode::NO_CONTENT
        }
        Err(e) => {
            error!("PUT /configs: reload failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub async fn patch_configs(State(state): State<ApiState>, Json(body): Json<Value>) -> StatusCode {
    let mut changed = false;

    if let Some(mode) = body.get("mode").and_then(|v| v.as_str()) {
        let valid = matches!(mode, "rule" | "global" | "direct");
        if valid {
            let mut rt = state.app.runtime_config.write();
            if rt.mode != mode {
                info!("Tunnel mode changed: {} -> {}", rt.mode, mode);
                rt.mode = mode.to_string();
                changed = true;
            }
        } else {
            tracing::warn!("Invalid mode value: {}", mode);
        }
    }

    if let Some(level) = body.get("log-level").and_then(|v| v.as_str()) {
        let valid = matches!(
            level,
            "trace" | "debug" | "info" | "warning" | "warn" | "error" | "silent"
        );
        if valid {
            let mut rt = state.app.runtime_config.write();
            if rt.log_level != level {
                info!("Log level changed: {} -> {}", rt.log_level, level);
                rt.log_level = level.to_string();
                changed = true;
                // Attempt to update the tracing filter at runtime.
                // This requires a reload handle which we don't have yet,
                // so we log the change for now.
                info!(
                    "Log level updated to '{}' (runtime filter reload pending)",
                    level
                );
            }
        } else {
            tracing::warn!("Invalid log-level value: {}", level);
        }
    }

    if changed {
        info!("Config patched successfully");
    }

    StatusCode::NO_CONTENT
}

pub async fn post_configs_geo(State(_state): State<ApiState>) -> StatusCode {
    // TODO: update geodata files
    StatusCode::NO_CONTENT
}
