use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use super::ApiState;

pub async fn get_rules(State(state): State<ApiState>) -> Json<Value> {
    let rules: Vec<Value> = state
        .rule_engine
        .rules()
        .iter()
        .enumerate()
        .map(|(i, r)| {
            json!({
                "index": i,
                "type": r.rule_type,
                "payload": r.payload,
                "proxy": r.target,
                "size": -1,
            })
        })
        .collect();

    Json(json!({ "rules": rules }))
}

pub async fn get_rule_providers(State(_state): State<ApiState>) -> Json<Value> {
    Json(json!({ "providers": {} }))
}

pub async fn put_rule_provider(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
) -> StatusCode {
    // TODO: trigger rule provider update
    StatusCode::NO_CONTENT
}
