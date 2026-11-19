use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

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

/// mihomo compat: hub/route/dns.go queryDNS — the question, with the
/// requested type, goes to the resolver itself
/// (`resolver.DefaultResolver.ExchangeContext`): its answer cache and its
/// nameservers. Asking the controller about a name never allocates a fake IP.
/// The response has mihomo's shape: Status, the TC/RD/RA/AD/CD flags, the
/// Question and whichever of Answer / Authority / Additional have records.
pub async fn get_dns_query(
    State(state): State<ApiState>,
    Query(query): Query<DnsQuery>,
) -> Response {
    let error = |status: StatusCode, message: &str| {
        (status, Json(json!({ "message": message }))).into_response()
    };

    if !state.app.config().dns.enable {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "DNS section is disabled");
    }

    let name = query.name.unwrap_or_default();
    if name.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let qtype_str = query.qtype.as_deref().filter(|t| !t.is_empty());
    let Some(qtype) = dns_type_from_str(qtype_str.unwrap_or("A")) else {
        return error(StatusCode::BAD_REQUEST, "invalid query type");
    };

    let reply = match state.app.dns_resolver().query(&name, qtype).await {
        Ok(reply) => reply,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    match reply_json(&reply) {
        Some(json) => Json(json).into_response(),
        None => error(StatusCode::INTERNAL_SERVER_ERROR, "malformed DNS reply"),
    }
}

/// Render a DNS reply the way mihomo's queryDNS does.
fn reply_json(message: &[u8]) -> Option<Value> {
    let header = message.get(..12)?;
    let count = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);

    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..count(4) {
        let (name, next) = read_name(message, pos)?;
        let fixed = message.get(next..next + 4)?;
        questions.push(json!({
            "Name": name,
            "Qtype": u16::from_be_bytes([fixed[0], fixed[1]]),
            "Qclass": u16::from_be_bytes([fixed[2], fixed[3]]),
        }));
        pos = next + 4;
    }

    let mut reply = Map::new();
    reply.insert("Status".into(), json!(header[3] & 0x0f));
    reply.insert("Question".into(), Value::Array(questions));
    reply.insert("TC".into(), json!(header[2] & 0x02 != 0));
    reply.insert("RD".into(), json!(header[2] & 0x01 != 0));
    reply.insert("RA".into(), json!(header[3] & 0x80 != 0));
    reply.insert("AD".into(), json!(header[3] & 0x20 != 0));
    reply.insert("CD".into(), json!(header[3] & 0x10 != 0));

    for (section, records) in [
        ("Answer", count(6)),
        ("Authority", count(8)),
        ("Additional", count(10)),
    ] {
        let mut rendered = Vec::new();
        for _ in 0..records {
            rendered.push(record_json(message, &mut pos)?);
        }
        if !rendered.is_empty() {
            reply.insert(section.into(), Value::Array(rendered));
        }
    }
    Some(Value::Object(reply))
}

/// Render the resource record at `pos` — name, type, TTL and the RDATA as
/// text — and advance `pos` past it.
fn record_json(message: &[u8], pos: &mut usize) -> Option<Value> {
    let (name, fixed) = read_name(message, *pos)?;
    let header = message.get(fixed..fixed + 10)?;
    let rtype = u16::from_be_bytes([header[0], header[1]]);
    let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let rdata_at = fixed + 10;
    let rdata_end = rdata_at + u16::from_be_bytes([header[8], header[9]]) as usize;
    let data = rdata_text(message, rtype, rdata_at, message.get(rdata_at..rdata_end)?)?;
    *pos = rdata_end;
    Some(json!({ "name": name, "type": rtype, "TTL": ttl, "data": data }))
}

/// RDATA in presentation format — what miekg/dns prints after the header of
/// a record — for the types the controller can ask for; anything else in the
/// generic form of RFC 3597.
fn rdata_text(message: &[u8], rtype: u16, at: usize, rdata: &[u8]) -> Option<String> {
    let name_at = |offset: usize| read_name(message, at + offset).map(|(name, _)| name);
    let u16_at = |offset: usize| {
        let bytes = rdata.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    };

    Some(match rtype {
        1 => Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?).to_string(),
        28 => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?).to_string(),
        // NS, CNAME, PTR
        2 | 5 | 12 => name_at(0)?,
        // MX: preference, exchange
        15 => format!("{} {}", u16_at(0)?, name_at(2)?),
        // SRV: priority, weight, port, target
        33 => format!(
            "{} {} {} {}",
            u16_at(0)?,
            u16_at(2)?,
            u16_at(4)?,
            name_at(6)?
        ),
        // SOA: mname, rname, then serial, refresh, retry, expire, minimum
        6 => {
            let (mname, next) = read_name(message, at)?;
            let (rname, next) = read_name(message, next)?;
            let mut text = format!("{mname} {rname}");
            for field in message.get(next..next + 20)?.chunks(4) {
                let value = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
                text.push_str(&format!(" {value}"));
            }
            text
        }
        // TXT: length-prefixed strings, each quoted
        16 => {
            let mut strings = Vec::new();
            let mut rest = rdata;
            while let Some((&len, tail)) = rest.split_first() {
                let string = tail.get(..len as usize)?;
                strings.push(format!("\"{}\"", txt_escape(string)));
                rest = &tail[len as usize..];
            }
            strings.join(" ")
        }
        _ => format!("\\# {} {}", rdata.len(), hex::encode(rdata)),
    })
}

/// Escape a TXT string like miekg/dns: `"` and `\` with a backslash, bytes
/// outside printable ASCII as `\DDD`.
fn txt_escape(string: &[u8]) -> String {
    let mut text = String::new();
    for &byte in string {
        match byte {
            b'"' | b'\\' => {
                text.push('\\');
                text.push(byte as char);
            }
            b' '..=b'~' => text.push(byte as char),
            _ => text.push_str(&format!("\\{byte:03}")),
        }
    }
    text
}

/// Read the domain name at `pos`, following compression pointers; returns it
/// with its trailing dot and the position after the name.
fn read_name(message: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    // Bounded, so that a cycle of compression pointers cannot loop forever.
    for _ in 0..message.len() {
        let len = *message.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(pos + 2);
            pos = (len & 0x3f) << 8 | *message.get(pos + 1)? as usize;
        } else if len == 0 {
            if name.is_empty() {
                name.push('.');
            }
            return Some((name, end.unwrap_or(pos + 1)));
        } else {
            name.push_str(&String::from_utf8_lossy(
                message.get(pos + 1..pos + 1 + len)?,
            ));
            name.push('.');
            pos += 1 + len;
        }
    }
    None
}

pub async fn post_dns_flush(State(state): State<ApiState>) -> StatusCode {
    state.app.dns_resolver().flush_cache();
    StatusCode::NO_CONTENT
}

pub async fn post_fakeip_flush(State(state): State<ApiState>) -> StatusCode {
    state.app.dns_resolver().flush_fakeip();
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply to `example.com IN <qtype>`: header bytes 2-3 are `flags`,
    /// then `counts` records per section taken from `records` (raw bytes).
    fn message(qtype: u16, flags: [u8; 2], counts: [u8; 3], records: &[u8]) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, flags[0], flags[1], 0, 1];
        for count in counts {
            message.extend_from_slice(&[0, count]);
        }
        message.extend_from_slice(b"\x07example\x03com\x00");
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&[0, 1]);
        message.extend_from_slice(records);
        message
    }

    /// A record owned by the question name (compression pointer to offset 12).
    fn record(rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut record = vec![0xc0, 0x0c];
        record.extend_from_slice(&rtype.to_be_bytes());
        record.extend_from_slice(&[0, 1]);
        record.extend_from_slice(&ttl.to_be_bytes());
        record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        record.extend_from_slice(rdata);
        record
    }

    /// mihomo compat: hub/route/dns.go queryDNS — Status, flags, Question and
    /// one {name, type, TTL, data} object per record, `data` being the RDATA
    /// as miekg/dns prints it.
    #[test]
    fn reply_is_rendered_like_mihomo() {
        let records = [
            record(1, 60, &[203, 0, 113, 7]),
            record(28, 61, &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()),
            // CNAME www.example.com. — "www" then a pointer to the question name
            record(5, 62, b"\x03www\xc0\x0c"),
            record(15, 63, b"\x00\x0a\x04mail\xc0\x0c"),
            record(16, 64, b"\x05v=spf\x04a\"b\\"),
            record(33, 65, b"\x00\x01\x00\x02\x01\xbb\x03sip\xc0\x0c"),
            record(99, 66, &[0xde, 0xad]),
        ]
        .concat();
        let json = reply_json(&message(255, [0x81, 0x80], [7, 0, 0], &records)).unwrap();

        assert_eq!(
            json,
            json!({
                "Status": 0,
                "Question": [{ "Name": "example.com.", "Qtype": 255, "Qclass": 1 }],
                "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
                "Answer": [
                    { "name": "example.com.", "type": 1, "TTL": 60, "data": "203.0.113.7" },
                    { "name": "example.com.", "type": 28, "TTL": 61, "data": "2001:db8::1" },
                    { "name": "example.com.", "type": 5, "TTL": 62, "data": "www.example.com." },
                    { "name": "example.com.", "type": 15, "TTL": 63, "data": "10 mail.example.com." },
                    { "name": "example.com.", "type": 16, "TTL": 64, "data": "\"v=spf\" \"a\\\"b\\\\\"" },
                    { "name": "example.com.", "type": 33, "TTL": 65, "data": "1 2 443 sip.example.com." },
                    { "name": "example.com.", "type": 99, "TTL": 66, "data": "\\# 2 dead" },
                ],
            })
        );
    }

    /// A negative reply keeps its response code and shows the SOA under
    /// Authority; sections without records are left out, as in mihomo.
    #[test]
    fn negative_reply_keeps_status_and_authority() {
        let mut soa = b"\x02ns\xc0\x0c\x05admin\xc0\x0c".to_vec();
        for value in [2024u32, 7200, 900, 1209600, 300] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        let json = reply_json(&message(1, [0x81, 0x83], [0, 1, 0], &record(6, 300, &soa))).unwrap();

        assert_eq!(json["Status"], 3);
        assert_eq!(json.get("Answer"), None);
        assert_eq!(json.get("Additional"), None);
        assert_eq!(
            json["Authority"],
            json!([{
                "name": "example.com.",
                "type": 6,
                "TTL": 300,
                "data": "ns.example.com. admin.example.com. 2024 7200 900 1209600 300",
            }])
        );
    }

    #[test]
    fn truncated_reply_is_not_rendered() {
        let full = message(
            1,
            [0x81, 0x80],
            [1, 0, 0],
            &record(1, 60, &[203, 0, 113, 7]),
        );
        assert!(reply_json(&full).is_some());
        assert!(reply_json(&full[..full.len() - 1]).is_none());
        // A compression pointer pointing at itself must not loop forever.
        let looping = message(1, [0x81, 0x80], [1, 0, 0], &[0xc0, 0x1d]);
        assert!(reply_json(&looping).is_none());
    }
}
