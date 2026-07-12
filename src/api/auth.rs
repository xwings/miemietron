use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Authentication middleware — checks Bearer token or ?token= query param.
pub async fn auth_middleware(
    State(secret): State<String>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Always allow CORS preflight requests (OPTIONS) — the CORS layer handles them
    if request.method() == axum::http::Method::OPTIONS {
        return next.run(request).await;
    }

    // Skip auth for UI static files (mihomo compat)
    if request.uri().path().starts_with("/ui") {
        return next.run(request).await;
    }

    // If no secret configured, allow all
    if secret.is_empty() {
        return next.run(request).await;
    }

    // mihomo compat: hub/route/server.go authentication — a websocket upgrade
    // carrying a non-empty `?token=` is authenticated by the token ALONE (a
    // wrong token 401s even with a valid Bearer header); everything else must
    // send `Authorization: Bearer`. Plain requests never accept `?token=`.
    let is_websocket = request
        .headers()
        .get("Upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if is_websocket {
        if let Some(token) = query_param(request.uri().query(), "token") {
            if !token.is_empty() {
                if constant_time_eq(token.as_bytes(), secret.as_bytes()) {
                    return next.run(request).await;
                }
                return unauthorized();
            }
        }
    }

    // Check Authorization header
    if let Some(auth) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            let expected = format!("Bearer {secret}");
            if constant_time_eq(auth_str.as_bytes(), expected.as_bytes()) {
                return next.run(request).await;
            }
        }
    }

    unauthorized()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"message": "Unauthorized"})),
    )
        .into_response()
}

/// Extract a query parameter with percent-decoding (mihomo uses
/// r.URL.Query().Get, which decodes).
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let query = query?;
    for param in query.split('&') {
        if let Some((k, v)) = param.split_once('=') {
            if k == name {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_equal_strings() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"secret-token-123", b"secret-token-123"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_different_strings() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // Differ only in last byte
        assert!(!constant_time_eq(b"aaaa", b"aaab"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
