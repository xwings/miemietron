use axum::{
    extract::{ws, FromRequestParts, State, WebSocketUpgrade},
    http::Request,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tokio::time::{interval, Duration};

use super::ApiState;

/// GET /traffic — streams via WebSocket, or returns a one-second rate snapshot.
///
/// mihomo compat (`hub/route/server.go` `traffic`): `up`/`down` are per-second
/// **rates** (bytes/sec), not cumulative totals — OpenClash's toolbar renders
/// them directly as "B/S". The non-WS branch samples a 1-second delta so a plain
/// `curl -m 3 /traffic` (OpenClash) sees a real rate; totals go in
/// `upTotal`/`downTotal`.
pub async fn get_traffic(
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
        let (mut parts, _body) = request.into_parts();
        match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            Ok(ws) => ws.on_upgrade(move |socket| handle_traffic_ws(socket, state)),
            Err(e) => e.into_response(),
        }
    } else {
        let prev_up = state.app.stats.upload_total();
        let prev_down = state.app.stats.download_total();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let up = state.app.stats.upload_total();
        let down = state.app.stats.download_total();
        Json(json!({
            "up": up.saturating_sub(prev_up),
            "down": down.saturating_sub(prev_down),
            "upTotal": up,
            "downTotal": down,
        }))
        .into_response()
    }
}

async fn handle_traffic_ws(mut socket: ws::WebSocket, state: ApiState) {
    let mut ticker = interval(Duration::from_secs(1));
    let mut prev_up = state.app.stats.upload_total();
    let mut prev_down = state.app.stats.download_total();

    loop {
        ticker.tick().await;

        let up = state.app.stats.upload_total();
        let down = state.app.stats.download_total();
        let delta_up = up.saturating_sub(prev_up);
        let delta_down = down.saturating_sub(prev_down);
        prev_up = up;
        prev_down = down;

        let msg = json!({
            "up": delta_up,
            "down": delta_down,
            "upTotal": up,
            "downTotal": down,
        })
        .to_string();
        if socket.send(ws::Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}
