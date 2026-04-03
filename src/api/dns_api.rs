use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::ApiState;

#[derive(Deserialize)]
pub struct DnsQuery {
    name: Option<String>,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

pub async fn get_dns_query(
    State(state): State<ApiState>,
    Query(query): Query<DnsQuery>,
) -> Result<Json<Value>, StatusCode> {
    let name = query.name.unwrap_or_default();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    match state.dns_resolver.resolve(&name).await {
        Ok(ip) => Ok(Json(json!({
            "Status": 0,
            "Question": [{
                "Name": name,
                "Qtype": 1,
            }],
            "Answer": [{
                "Name": name,
                "TTL": 3600,
                "Data": ip.to_string(),
            }],
        }))),
        Err(e) => Ok(Json(json!({
            "Status": 2,
            "Question": [{
                "Name": name,
                "Qtype": 1,
            }],
            "Answer": [],
            "Comment": e.to_string(),
        }))),
    }
}

pub async fn post_dns_flush(State(state): State<ApiState>) -> StatusCode {
    state.dns_resolver.flush_cache();
    StatusCode::NO_CONTENT
}

pub async fn post_fakeip_flush(State(state): State<ApiState>) -> StatusCode {
    state.dns_resolver.flush_fakeip();
    StatusCode::NO_CONTENT
}
