use axum::{
    extract::{ws, FromRequestParts, Path, State, WebSocketUpgrade},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tokio::time::{interval, Duration};

use super::ApiState;

/// GET /connections — returns JSON snapshot or streams via WebSocket.
///
/// - WebSocket: streams full connection snapshots at `?interval=N` ms (default 1000)
/// - HTTP GET: returns single snapshot
pub async fn get_connections(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
) -> Response {
    let is_ws = request
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_ws {
        // mihomo compat: read ?interval=N (milliseconds) before upgrading
        let interval_ms = request
            .uri()
            .query()
            .and_then(|q| {
                q.split('&')
                    .find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        if k == "interval" { v.parse::<u64>().ok() } else { None }
                    })
            })
            .unwrap_or(1000);

        let (mut parts, _body) = request.into_parts();
        match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            Ok(ws) => ws.on_upgrade(move |socket| handle_connections_ws(socket, state, interval_ms)),
            Err(e) => e.into_response(),
        }
    } else {
        let snapshot = state.conn_manager.snapshot();
        Json(json!({
            "downloadTotal": snapshot.download_total,
            "uploadTotal": snapshot.upload_total,
            "connections": snapshot.connections,
            "memory": snapshot.memory,
        }))
        .into_response()
    }
}

async fn handle_connections_ws(mut socket: ws::WebSocket, state: ApiState, interval_ms: u64) {
    let mut ticker = interval(Duration::from_millis(interval_ms.max(100)));

    loop {
        ticker.tick().await;

        let snapshot = state.conn_manager.snapshot();
        let msg = json!({
            "downloadTotal": snapshot.download_total,
            "uploadTotal": snapshot.upload_total,
            "connections": snapshot.connections,
            "memory": snapshot.memory,
        })
        .to_string();

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
    if state.conn_manager.close_connection(&id) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}
