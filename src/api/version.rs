use axum::{
    extract::{ws, FromRequestParts, State, WebSocketUpgrade},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use tokio::time::{interval, Duration};

use super::ApiState;

/// GET / — mihomo returns {"hello": "mihomo"} at root.
pub async fn get_hello() -> Json<Value> {
    Json(json!({"hello": "mihomo"}))
}

/// GET /version — returns version info.
pub async fn get_version() -> Json<Value> {
    Json(json!({
        "meta": true,
        "version": format!("v{}", env!("CARGO_PKG_VERSION")),
        "premium": false,
    }))
}

/// GET /memory — returns memory usage or streams via WebSocket.
///
/// - WebSocket: streams `{"inuse": bytes, "oslimit": 0}` every second
/// - HTTP GET: returns single snapshot
pub async fn get_memory(
    State(_state): State<ApiState>,
    request: Request<axum::body::Body>,
) -> Response {
    let is_ws = request
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_ws {
        let (mut parts, _body) = request.into_parts();
        match WebSocketUpgrade::from_request_parts(&mut parts, &_state).await {
            Ok(ws) => ws.on_upgrade(handle_memory_ws),
            Err(e) => e.into_response(),
        }
    } else {
        let inuse = get_memory_usage();
        Json(json!({
            "inuse": inuse,
            "oslimit": 0,
        }))
        .into_response()
    }
}

async fn handle_memory_ws(mut socket: ws::WebSocket) {
    let mut ticker = interval(Duration::from_secs(1));
    // mihomo compat: first message sends 0 to make chart.js begin with zero
    let mut first = true;

    loop {
        ticker.tick().await;

        let inuse = if first {
            first = false;
            0
        } else {
            get_memory_usage()
        };
        let msg = json!({"inuse": inuse, "oslimit": 0}).to_string();
        if socket.send(ws::Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

pub async fn post_restart(State(state): State<ApiState>) -> Json<Value> {
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
