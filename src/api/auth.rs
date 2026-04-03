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
    // If no secret configured, allow all
    if secret.is_empty() {
        return next.run(request).await;
    }

    // Check Authorization header
    if let Some(auth) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            let expected = format!("Bearer {}", secret);
            if constant_time_eq(auth_str.as_bytes(), expected.as_bytes()) {
                return next.run(request).await;
            }
        }
    }

    // Check query param ?token=
    if let Some(query) = request.uri().query() {
        for param in query.split('&') {
            if let Some(token) = param.strip_prefix("token=") {
                if constant_time_eq(token.as_bytes(), secret.as_bytes()) {
                    return next.run(request).await;
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "Unauthorized"})),
    )
        .into_response()
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
