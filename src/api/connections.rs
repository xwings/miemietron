use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use super::ApiState;

/// GET /connections - returns JSON snapshot of active connections.
pub async fn get_connections(State(state): State<ApiState>) -> Json<Value> {
    let snapshot = state.conn_manager.snapshot();
    Json(json!({
        "downloadTotal": snapshot.download_total,
        "uploadTotal": snapshot.upload_total,
        "connections": snapshot.connections,
        "memory": snapshot.memory,
    }))
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
