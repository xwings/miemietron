use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::IpAddr;

use super::ApiState;

#[derive(Deserialize)]
pub struct DnsQuery {
    name: Option<String>,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

/// Map DNS type string to numeric type (subset matching mihomo/miekg/dns).
fn dns_type_from_str(s: &str) -> Option<u16> {
    match s.to_uppercase().as_str() {
        "A" => Some(1),
        "AAAA" => Some(28),
        "CNAME" => Some(5),
        "MX" => Some(15),
        "NS" => Some(2),
        "PTR" => Some(12),
        "SOA" => Some(6),
        "SRV" => Some(33),
        "TXT" => Some(16),
        "ANY" => Some(255),
        _ => None,
    }
}

/// mihomo compat: response format matches mihomo's queryDNS handler
/// with Status, TC, RD, RA, AD, CD flags and typed Answer entries.
pub async fn get_dns_query(
    State(state): State<ApiState>,
    Query(query): Query<DnsQuery>,
) -> Result<Json<Value>, StatusCode> {
    let name = query.name.unwrap_or_default();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let qtype_str = query.qtype.as_deref().unwrap_or("A");
    let qtype = match dns_type_from_str(qtype_str) {
        Some(t) => t,
        None => {
            return Ok(Json(json!({
                "Status": 1,
                "Comment": "invalid query type",
            })));
        }
    };

    // Ensure the name ends with a dot (FQDN) for the Question field
    let fqdn = if name.ends_with('.') {
        name.clone()
    } else {
        format!("{name}.")
    };

    let dns_resolver = state.app.dns_resolver();
    match dns_resolver.resolve(&name).await {
        Ok(ip) => {
            // Determine the actual answer type based on the IP version
            let answer_type: u16 = match ip {
                IpAddr::V4(_) => 1,  // A
                IpAddr::V6(_) => 28, // AAAA
            };

            Ok(Json(json!({
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [{
                    "Name": fqdn,
                    "Qtype": qtype,
                    "Qclass": 1,
                }],
                "Answer": [{
                    "name": fqdn,
                    "type": answer_type,
                    "TTL": 600,
                    "data": ip.to_string(),
                }],
            })))
        }
        Err(e) => Ok(Json(json!({
            "Status": 2,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [{
                "Name": fqdn,
                "Qtype": qtype,
                "Qclass": 1,
            }],
            "Comment": e.to_string(),
        }))),
    }
}

pub async fn post_dns_flush(State(state): State<ApiState>) -> StatusCode {
    state.app.dns_resolver().flush_cache();
    StatusCode::NO_CONTENT
}

pub async fn post_fakeip_flush(State(state): State<ApiState>) -> StatusCode {
    state.app.dns_resolver().flush_fakeip();
    StatusCode::NO_CONTENT
}
