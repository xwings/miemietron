use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use super::ApiState;

pub async fn get_version() -> Json<Value> {
    Json(json!({
        "meta": true,
        "version": format!("v{}", env!("CARGO_PKG_VERSION")),
        "premium": false,
    }))
}

pub async fn get_memory() -> Json<Value> {
    let inuse = get_memory_usage();
    Json(json!({
        "inuse": inuse,
        "oslimit": 0,
    }))
}

pub async fn get_gc() -> StatusCode {
    // Rust has no GC, but we honor the endpoint for compatibility
    StatusCode::OK
}

pub async fn post_restart(State(state): State<ApiState>) -> Json<Value> {
    // Send a restart signal to the main loop, which performs a full config reload
    // (rebuilds DNS, rules, proxies — equivalent to SIGHUP).
    let _ = state.app.restart_tx.try_send(());
    tracing::info!("Restart requested via API");
    Json(json!({"status": "ok"}))
}

/// POST /upgrade — core self-upgrade stub.
pub async fn post_upgrade_stub() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

/// PUT /debug/gc — trigger GC (no-op in Rust).
pub async fn put_debug_gc() -> StatusCode {
    StatusCode::OK
}

fn get_memory_usage() -> u64 {
    if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pages) = parts[1].parse::<u64>() {
                return pages * 4096;
            }
        }
    }
    0
}
