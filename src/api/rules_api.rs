use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

use super::ApiState;

pub async fn get_rules(State(state): State<ApiState>) -> Json<Value> {
    use std::sync::atomic::Ordering;

    let rule_engine = state.app.rule_engine();
    let stats = rule_engine.rule_stats();
    let rules: Vec<Value> = rule_engine
        .rules()
        .iter()
        .enumerate()
        .map(|(i, r)| {
            // mihomo compat: GEOIP and GEOSITE rules report their database size
            let size = rule_engine.rule_record_size(&r.rule_type, &r.payload);
            let (hit_count, disabled) = stats
                .get(i)
                .map(|s| {
                    (
                        s.hit_count.load(Ordering::Relaxed),
                        s.disabled.load(Ordering::Relaxed),
                    )
                })
                .unwrap_or((0, false));
            json!({
                "index": i,
                "type": r.rule_type,
                "payload": r.payload,
                "proxy": r.target,
                "size": size,
                "extra": {
                    "hitCount": hit_count,
                    "disabled": disabled
                }
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
    Path(name): Path<String>,
) -> StatusCode {
    // mihomo compat: PUT /providers/rules/:name triggers a provider update.
    // Full provider reload is not yet implemented; log and return success.
    tracing::info!("Rule provider update requested for '{}'", name);
    StatusCode::NO_CONTENT
}

/// PATCH /rules/disable — enable/disable specific rules by index.
/// mihomo compat: accepts JSON body with "index" (usize) and "disabled" (bool).
pub async fn patch_rules_disable(
    State(state): State<ApiState>,
    Json(body): Json<Value>,
) -> StatusCode {
    use std::sync::atomic::Ordering;

    let index = match body.get("index").and_then(|v| v.as_u64()) {
        Some(i) => i as usize,
        None => return StatusCode::BAD_REQUEST,
    };

    let disabled = match body.get("disabled").and_then(|v| v.as_bool()) {
        Some(d) => d,
        None => return StatusCode::BAD_REQUEST,
    };

    let rule_engine = state.app.rule_engine();
    let stats = rule_engine.rule_stats();

    match stats.get(index) {
        Some(s) => {
            s.disabled.store(disabled, Ordering::Relaxed);
            tracing::info!("Rule[{}] disabled={}", index, disabled);
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}
