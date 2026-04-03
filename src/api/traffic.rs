use axum::{extract::State, Json};
use serde_json::{json, Value};

use super::ApiState;

/// GET /traffic — returns current traffic snapshot.
/// mihomo streams this over WebSocket; we return a JSON snapshot for now.
pub async fn get_traffic(State(state): State<ApiState>) -> Json<Value> {
    Json(json!({
        "up": state.app.stats.upload_total(),
        "down": state.app.stats.download_total(),
    }))
}
