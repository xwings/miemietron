use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

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

pub async fn post_restart() -> Json<Value> {
    // TODO: implement graceful restart
    Json(json!({"status": "ok"}))
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
