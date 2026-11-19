//! What a REALITY client does once it knows the server is not REALITY's.
//!
//! The handshake completed against a certificate that is valid for the
//! camouflage name: the real site answered (wrong key, wrong short ID, a
//! server that gave up on us) or someone is relaying to it. Hanging up at
//! that point is what a browser would never do, so mihomo carries on as one:
//! an HTTP/2 request for the front page, a pause, then goodbye.

use rand::rngs::OsRng;
use rand::Rng;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// mihomo compat: `realityClientFallback` (`component/tls/reality.go`).
pub(super) async fn browse<S>(stream: S, server_name: String, user_agent: &'static str)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Go speaks HTTP/2 here whatever ALPN settled on, so its client can
    // never fall back to HTTP/1.1.
    let Ok((mut sender, connection)) = h2::client::handshake(stream).await else {
        return;
    };
    let connection = tokio::spawn(connection);

    let padding = "0".repeat(OsRng.gen_range(0..32) + 30);
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{server_name}"))
        .header(http::header::USER_AGENT, user_agent)
        .header(http::header::COOKIE, format!("padding={padding}"))
        // Go's transport asks for gzip on its own.
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(());
    if let Ok(request) = request {
        if let Ok((response, _)) = sender.send_request(request, true) {
            if response.await.is_ok() {
                tokio::time::sleep(Duration::from_secs(5 + OsRng.gen_range(0..10))).await;
            }
        }
    }
    connection.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn fetches_the_front_page_then_lingers_like_a_browser() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(browse(client_io, "example.com".to_string(), "Chrome"));

        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().to_string(), "https://example.com/");
        assert_eq!(request.headers()[http::header::USER_AGENT], "Chrome");
        let cookie = request.headers()[http::header::COOKIE].to_str().unwrap();
        let padding = cookie.strip_prefix("padding=").unwrap();
        assert!((30..62).contains(&padding.len()));
        assert!(padding.bytes().all(|byte| byte == b'0'));

        let started = tokio::time::Instant::now();
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
        // Keep serving until the client hangs up, 5 to 14 seconds later.
        while connection.accept().await.is_some() {}
        client.await.unwrap();
        let lingered = started.elapsed();
        assert!(lingered >= Duration::from_secs(5) && lingered < Duration::from_secs(15));
    }

    #[tokio::test]
    async fn gives_up_quietly_on_a_server_without_http2() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        drop(server_io);
        browse(client_io, "example.com".to_string(), "Chrome").await;
    }
}
