use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::ApiState;

pub async fn get_proxies(State(state): State<ApiState>) -> Json<Value> {
    let proxies: HashMap<String, Value> = state
        .proxy_manager
        .list_proxies()
        .into_iter()
        .map(|p| {
            let name = p.name.clone();
            let val = json!({
                "name": p.name,
                "type": p.proxy_type,
                "udp": p.udp,
                "history": [],
                "all": [],
                "now": "",
                "alive": true,
            });
            (name, val)
        })
        .collect();

    Json(json!({ "proxies": proxies }))
}

pub async fn get_proxy(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    if let Some(handler) = state.proxy_manager.get(&name) {
        Ok(Json(json!({
            "name": handler.name(),
            "type": handler.proto(),
            "udp": handler.supports_udp(),
            "history": [],
            "all": [],
            "now": "",
            "alive": true,
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct DelayQuery {
    url: Option<String>,
    timeout: Option<u64>,
    expected: Option<String>,
}

pub async fn get_proxy_delay(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
    Query(_query): Query<DelayQuery>,
) -> Json<Value> {
    // TODO: implement delay test
    Json(json!({"delay": 0}))
}

#[derive(Deserialize)]
pub struct SelectBody {
    name: String,
}

pub async fn put_proxy(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
    Json(_body): Json<SelectBody>,
) -> StatusCode {
    // TODO: select proxy in group
    StatusCode::NO_CONTENT
}

pub async fn delete_proxy(State(_state): State<ApiState>, Path(_name): Path<String>) -> StatusCode {
    // TODO: clear forced selection
    StatusCode::NO_CONTENT
}

// --- Groups ---

pub async fn get_groups(State(state): State<ApiState>) -> Json<Value> {
    let groups: HashMap<String, Value> = state
        .proxy_manager
        .list_groups()
        .iter()
        .map(|g| {
            let name = g.name.clone();
            let val = json!({
                "name": g.name,
                "type": g.group_type,
                "udp": true,
                "history": [],
                "all": g.proxies,
                "now": g.proxies.first().unwrap_or(&String::new()),
                "alive": true,
            });
            (name, val)
        })
        .collect();

    Json(json!({ "proxies": groups }))
}

pub async fn get_group(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    for g in state.proxy_manager.list_groups() {
        if g.name == name {
            return Ok(Json(json!({
                "name": g.name,
                "type": g.group_type,
                "udp": true,
                "history": [],
                "all": g.proxies,
                "now": g.proxies.first().unwrap_or(&String::new()),
                "alive": true,
            })));
        }
    }
    Err(StatusCode::NOT_FOUND)
}

pub async fn get_group_delay(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
    Query(_query): Query<DelayQuery>,
) -> Json<Value> {
    // TODO: test all proxies in group
    Json(json!({}))
}

// --- Providers ---

pub async fn get_providers(State(_state): State<ApiState>) -> Json<Value> {
    Json(json!({ "providers": {} }))
}

pub async fn get_provider(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    Err(StatusCode::NOT_FOUND)
}

pub async fn put_provider(State(_state): State<ApiState>, Path(_name): Path<String>) -> StatusCode {
    // TODO: trigger provider update
    StatusCode::NO_CONTENT
}

pub async fn get_provider_healthcheck(
    State(_state): State<ApiState>,
    Path(_name): Path<String>,
) -> StatusCode {
    StatusCode::NO_CONTENT
}
