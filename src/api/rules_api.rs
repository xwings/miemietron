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

/// `GET /providers/rules` — list every rule provider loaded by the engine.
///
/// Returns `{ "providers": { name: { name, type, vehicleType, behavior,
/// format, ruleCount, updatedAt }, ... } }`. `ruleCount` is the actual rule
/// count ingested at load time; `updatedAt` is the ISO-8601 timestamp at
/// which the engine ingested the provider.
///
/// **Partial behavior, by design.** miemietron consumes providers at
/// engine-construction time and merges their rules into shared indexes —
/// the live `RuleProvider` objects are not retained. Consequently:
///
/// - `ruleCount` and `updatedAt` reflect the load-time snapshot, not a live
///   state. They do not change between config reloads.
/// - `PUT /providers/rules/:name` cannot trigger a runtime re-fetch and
///   returns 503 (see `put_rule_provider`).
///
/// This trade-off is documented in ARCHITECTURE.md ("Scope") so dashboards
/// don't expect live reload.
pub async fn get_rule_providers(State(state): State<ApiState>) -> Json<Value> {
    let engine = state.app.rule_engine();
    let info = engine.provider_info();
    let mut providers = serde_json::Map::new();
    for (name, pi) in info {
        providers.insert(name.clone(), provider_json(pi));
    }
    Json(json!({ "providers": providers }))
}

/// `GET /providers/rules/:name` — single provider details.
///
/// Returns 404 with `{ "message": "resource not found" }` when the named
/// provider is not in the engine's loaded set.
pub async fn get_rule_provider(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    let engine = state.app.rule_engine();
    if let Some(pi) = engine.provider_info().get(&name) {
        (StatusCode::OK, Json(provider_json(pi)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "resource not found" })),
        )
    }
}

/// `PUT /providers/rules/:name` — runtime re-fetch is **not supported** in
/// miemietron. mihomo's PUT here triggers `provider.Update()` which
/// re-pulls the remote URL into the live provider; we don't keep the live
/// provider after engine construction (rules are merged into shared
/// indexes). Returning 503 with a clear message is the honest answer —
/// returning 204 would lie about the operation having taken effect.
pub async fn put_rule_provider(
    State(_state): State<ApiState>,
    Path(name): Path<String>,
) -> (StatusCode, Json<Value>) {
    tracing::info!(
        "Rule provider runtime update requested for '{}', not supported",
        name
    );
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "message": "provider runtime reload is not supported in miemietron — \
                        edit config and SIGHUP/reload to re-ingest providers"
        })),
    )
}

fn provider_json(pi: &crate::rules::RuleProviderInfo) -> Value {
    json!({
        "name": pi.name,
        "type": "Rule",
        "vehicleType": pi.vehicle_type,
        "behavior": pi.behavior,
        "format": pi.format,
        "ruleCount": pi.rule_count,
        "updatedAt": format_unix_iso8601(pi.updated_at_unix),
    })
}

/// Format a unix-seconds timestamp as RFC 3339 / ISO 8601 in UTC.
/// Matches the wire shape mihomo produces for `updatedAt`.
fn format_unix_iso8601(secs: u64) -> String {
    use chrono::{DateTime, Utc};
    if secs == 0 {
        return String::new();
    }
    DateTime::<Utc>::from_timestamp(secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
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
