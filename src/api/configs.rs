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

    // mihomo compat: GeoXUrl serializes as `geo-ip` / `geo-site` / `mmdb` /
    // `asn` (config.go:94-99), with the MetaCubeX default URLs when unset
    // (config.go:571-576).
    let geox_url = {
        let empty = std::collections::HashMap::new();
        let map = config.geox_url.as_ref().unwrap_or(&empty);
        let get = |k: &str, default: &str| -> String {
            map.get(k)
                .cloned()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        json!({
            "geo-ip": get("geoip", crate::rules::geodata::DEFAULT_GEOIP_DAT_URL),
            "mmdb": get("mmdb", crate::rules::geodata::DEFAULT_MMDB_URL),
            "asn": get("asn", crate::rules::geodata::DEFAULT_ASN_URL),
            "geo-site": get("geosite", crate::rules::geodata::DEFAULT_GEOSITE_URL),
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
    force: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PutConfigsBody {
    path: String,
    payload: String,
}

/// PUT /configs — full config reload.
///
/// mihomo compat: hub/route/configs.go `updateConfigs`. A non-empty `payload`
/// is the config itself; otherwise `path` names it, and an empty `path` means
/// the file the core was started with — which is what both dashboards send
/// for "reload config" (`{"path": "", "payload": ""}`). The body is decoded
/// whatever its Content-Type says.
pub async fn put_configs(
    State(state): State<ApiState>,
    Query(query): Query<PutConfigsQuery>,
    body: axum::body::Bytes,
) -> Response {
    let Ok(body) = serde_json::from_slice::<PutConfigsBody>(&body) else {
        return config_error(StatusCode::BAD_REQUEST, "Body invalid");
    };
    let force = query.force.as_deref() == Some("true");

    let result = if !body.payload.is_empty() {
        info!(
            "PUT /configs: reloading from payload ({} bytes, force={})",
            body.payload.len(),
            force
        );
        state.app.reload_from_str(&body.payload).await
    } else {
        let path = if body.path.is_empty() {
            state.app.config_path.read().clone()
        } else {
            let path = std::path::PathBuf::from(&body.path);
            if !path.is_absolute() {
                return config_error(StatusCode::BAD_REQUEST, "path is not a absolute path");
            }
            path
        };
        info!(
            "PUT /configs: reloading from path: {} (force={})",
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
            return config_error(StatusCode::BAD_REQUEST, &format!("invalid mode: {mode}"));
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

/// POST /configs/geo (and /upgrade/geo) — download fresh geo databases.
/// mihomo compat: hub/route/configs.go:438-448 → updater.UpdateGeoDatabases;
/// failure returns 500 with the message, success 204. A reload afterwards
/// re-opens the databases (mihomo's updater reloads the config on success).
pub async fn post_configs_geo(State(state): State<ApiState>) -> Response {
    let home_dir = state.app.home_dir.clone();
    let geox = state.app.config().geox_url.clone();
    match crate::rules::geodata::update_geo_databases(&home_dir, geox.as_ref()).await {
        Ok(()) => {
            tracing::info!("Geo databases updated, reloading config to apply");
            let _ = state.app.restart_tx.try_send(());
            // mihomo compat: 204 with an EMPTY body (see put_configs).
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => config_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::ConnectionManager;
    use std::sync::Arc;

    async fn state() -> ApiState {
        let app = crate::conn::test_support::app_state("mode: rule\n").await;
        ApiState {
            conn_manager: Arc::new(ConnectionManager::new(app.clone())),
            app,
        }
    }

    async fn put(state: &ApiState, body: &str) -> (StatusCode, String) {
        let response = put_configs(
            State(state.clone()),
            Query(PutConfigsQuery::default()),
            axum::body::Bytes::copy_from_slice(body.as_bytes()),
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    /// mihomo compat: hub/route/configs.go updateConfigs.
    #[tokio::test]
    async fn put_configs_reloads_like_mihomo() {
        let state = state().await;
        let dir = tempfile::tempdir().unwrap();
        let on_disk = dir.path().join("config.yaml");
        std::fs::write(&on_disk, "mode: direct\n").unwrap();
        *state.app.config_path.write() = on_disk.clone();
        let mode = || state.app.runtime_config.read().mode.clone();

        // What both dashboards send for "reload config": the file the core
        // was started with.
        assert_eq!(
            put(&state, r#"{"path": "", "payload": ""}"#).await,
            (StatusCode::NO_CONTENT, String::new())
        );
        assert_eq!(mode(), "direct");

        // A payload wins over a path.
        let body = format!(
            r#"{{"path": {:?}, "payload": "mode: global\n"}}"#,
            on_disk.display().to_string()
        );
        assert_eq!(put(&state, &body).await.0, StatusCode::NO_CONTENT);
        assert_eq!(mode(), "global");

        // An explicit path is read, and does not become the default one.
        let other = dir.path().join("other.yaml");
        std::fs::write(&other, "mode: rule\n").unwrap();
        let body = format!(r#"{{"path": {:?}}}"#, other.display().to_string());
        assert_eq!(put(&state, &body).await.0, StatusCode::NO_CONTENT);
        assert_eq!(mode(), "rule");
        assert_eq!(*state.app.config_path.read(), on_disk);

        assert_eq!(
            put(&state, r#"{"path": "relative.yaml"}"#).await,
            (
                StatusCode::BAD_REQUEST,
                r#"{"message":"path is not a absolute path"}"#.to_string()
            )
        );
        assert_eq!(
            put(&state, "not json").await,
            (
                StatusCode::BAD_REQUEST,
                r#"{"message":"Body invalid"}"#.to_string()
            )
        );
    }
}
