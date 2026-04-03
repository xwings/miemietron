use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use super::ApiState;

pub async fn get_configs(State(state): State<ApiState>) -> Json<Value> {
    let config = &state.config;
    Json(json!({
        "port": config.port,
        "socks-port": config.socks_port,
        "redir-port": config.redir_port,
        "tproxy-port": config.tproxy_port,
        "mixed-port": config.mixed_port,
        "allow-lan": config.allow_lan,
        "bind-address": config.bind_address,
        "mode": config.mode,
        "log-level": config.log_level,
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

pub async fn put_configs(State(_state): State<ApiState>, Json(_body): Json<Value>) -> StatusCode {
    // TODO: reload config from path/payload
    StatusCode::NO_CONTENT
}

pub async fn patch_configs(State(_state): State<ApiState>, Json(_body): Json<Value>) -> StatusCode {
    // TODO: partial config update (mode, log-level, tun, etc.)
    StatusCode::NO_CONTENT
}

pub async fn post_configs_geo(State(_state): State<ApiState>) -> StatusCode {
    // TODO: update geodata files
    StatusCode::NO_CONTENT
}
