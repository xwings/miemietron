//! HTTP/HTTPS proxy inbound listener.
//!
//! Supports both plain HTTP relay (GET/POST/...) and CONNECT tunnelling.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

use crate::conn::ConnectionManager;

/// Start an HTTP proxy listener on `addr`.
pub async fn run_http_proxy(
    addr: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth: Arc<Vec<String>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("HTTP proxy listening on {}", addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("HTTP accept error: {}", e);
                continue;
            }
        };

        let cm = conn_manager.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(stream, peer, cm, &auth).await {
                warn!("HTTP connection from {} error: {}", peer, e);
            }
        });
    }
}

/// Parse the first request line to determine whether this is a CONNECT tunnel
/// or a regular HTTP proxy request, then hand to ConnectionManager.
async fn handle_http_connection(
    stream: TcpStream,
    peer: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth_list: &[String],
) -> Result<()> {
    let require_auth = !auth_list.is_empty();

    let mut buf_reader = BufReader::new(stream);

    // Read the request line (e.g. "CONNECT example.com:443 HTTP/1.1\r\n")
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim_end().to_string();

    if request_line.is_empty() {
        return Err(anyhow!("empty request line"));
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("malformed request line: {}", request_line));
    }

    let method = parts[0].to_uppercase();
    let target_str = parts[1];

    // Consume remaining headers, looking for Proxy-Authorization
    let mut proxy_auth: Option<String> = None;
    loop {
        let mut header_line = String::new();
        buf_reader.read_line(&mut header_line).await?;
        if header_line.trim().is_empty() {
            break;
        }
        // Check for Proxy-Authorization header (case-insensitive)
        let lower = header_line.to_lowercase();
        if lower.starts_with("proxy-authorization:") {
            let value = header_line
                .split_once(':')
                .map(|(_, v)| v)
                .unwrap_or("")
                .trim()
                .to_string();
            proxy_auth = Some(value);
        }
    }

    // Validate authentication if required
    if require_auth {
        let authenticated = if let Some(ref auth_value) = proxy_auth {
            // Expected format: "Basic base64(user:pass)"
            if let Some(encoded) = auth_value.strip_prefix("Basic ") {
                if let Ok(decoded) = base64_decode(encoded.trim()) {
                    // decoded is "user:pass"
                    auth_list.iter().any(|entry| entry == &decoded)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if !authenticated {
            let mut inner = buf_reader.into_inner();
            inner
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            return Err(anyhow!("HTTP proxy auth failed from {}", peer));
        }
    }

    let (host, port) = if method == "CONNECT" {
        // CONNECT host:port HTTP/1.1
        parse_host_port(target_str, 443)?
    } else {
        // Regular HTTP: GET http://host:port/path HTTP/1.1
        parse_http_url(target_str)?
    };

    // Build a dummy SocketAddr — the ConnectionManager will use the host_override
    // for domain-based rule matching and proxy dispatch. We only need a real
    // SocketAddr for IP-literal targets.
    let dst: SocketAddr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        SocketAddr::new(ip, port)
    } else {
        // Use a placeholder IP; the domain name is passed via host_override
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port)
    };

    let host_override = if host.parse::<std::net::IpAddr>().is_err() {
        Some(host.clone())
    } else {
        None
    };

    if method == "CONNECT" {
        // Send 200 Connection Established before handing off
        let mut inner = buf_reader.into_inner();
        inner
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        conn_manager
            .handle_tcp_with_host(peer, dst, inner, "http-connect", host_override)
            .await?;
    } else {
        let inner = buf_reader.into_inner();
        conn_manager
            .handle_tcp_with_host(peer, dst, inner, "http-proxy", host_override)
            .await?;
    }

    Ok(())
}

/// Parse "host:port" with a default port.
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port: u16 = s[idx + 1..].parse().unwrap_or(default_port);
        Ok((host.to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// Extract host and port from an absolute HTTP URL.
fn parse_http_url(url_str: &str) -> Result<(String, u16)> {
    // Strip scheme
    let without_scheme = if let Some(rest) = url_str.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url_str.strip_prefix("https://") {
        rest
    } else {
        url_str
    };

    // Take host:port part (before the first '/')
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    parse_host_port(authority, 80)
}

/// Handle a single already-accepted HTTP proxy connection (used by the
/// mixed-port listener).
pub async fn run_http_single(
    stream: TcpStream,
    peer: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth: Arc<Vec<String>>,
) -> Result<()> {
    handle_http_connection(stream, peer, conn_manager, &auth).await
}

/// Decode a base64 string to a UTF-8 string.
fn base64_decode(input: &str) -> Result<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| anyhow!("base64 decode error: {}", e))?;
    String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 decode error: {}", e))
}

