use axum::{
    extract::{ws, Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tokio::time::{interval, Duration};

use super::ApiState;

/// Build the full connections snapshot JSON shared by the HTTP and WS branches.
fn snapshot_json(state: &ApiState) -> serde_json::Value {
    let snapshot = state.conn_manager.snapshot();
    json!({
        "downloadTotal": snapshot.download_total,
        "uploadTotal": snapshot.upload_total,
        "connections": snapshot.connections,
        "memory": snapshot.memory,
    })
}

/// GET /connections — returns JSON snapshot or streams via WebSocket.
///
/// - WebSocket: streams full connection snapshots at `?interval=N` ms (default 1000)
/// - HTTP GET: returns single snapshot
pub async fn get_connections(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
) -> Response {
    // mihomo compat: read ?interval=N (milliseconds) before upgrading
    let interval_ms = request
        .uri()
        .query()
        .and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "interval" {
                    v.parse::<u64>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(1000);

    match super::websocket_upgrade(request).await {
        Some(Ok(ws)) => {
            ws.on_upgrade(move |socket| handle_connections_ws(socket, state, interval_ms))
        }
        Some(Err(resp)) => resp,
        None => Json(snapshot_json(&state)).into_response(),
    }
}

async fn handle_connections_ws(mut socket: ws::WebSocket, state: ApiState, interval_ms: u64) {
    let mut ticker = interval(Duration::from_millis(interval_ms.max(100)));

    loop {
        ticker.tick().await;

        let msg = snapshot_json(&state).to_string();

        if socket.send(ws::Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

/// DELETE /connections - close all connections.
pub async fn delete_connections(State(state): State<ApiState>) -> StatusCode {
    state.conn_manager.close_all();
    StatusCode::NO_CONTENT
}

/// DELETE /connections/:id - close a specific connection.
pub async fn delete_connection(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> StatusCode {
    // mihomo compat: connections.go:73-79 — always 204, even for unknown ids.
    let _ = state.conn_manager.close_connection(&id);
    StatusCode::NO_CONTENT
}
