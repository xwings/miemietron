//! Inbound proxy listeners: HTTP, SOCKS5, mixed-port, and transparent proxy (redir).
//!
//! These listeners accept connections from local applications (as an
//! alternative to TUN) and hand them to the ConnectionManager for
//! rule-matching and proxying.

pub mod http;
pub mod redir;
pub mod socks;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::conn::ConnectionManager;

/// Start a mixed-port listener that auto-detects SOCKS5 vs HTTP by peeking
/// at the first byte of each connection.
///
/// - 0x05 -> SOCKS5 handshake
/// - anything else -> HTTP proxy
pub async fn run_mixed_proxy(
    addr: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth: Arc<Vec<String>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Mixed (HTTP+SOCKS5) proxy listening on {}", addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Mixed accept error: {}", e);
                continue;
            }
        };

        let cm = conn_manager.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_mixed(stream, peer, cm, auth).await {
                debug!("Mixed connection from {} ended: {}", peer, e);
            }
        });
    }
}

/// Peek the first byte to decide protocol, then delegate.
async fn handle_mixed(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    auth: Arc<Vec<String>>,
) -> Result<()> {
    // Peek the first byte without consuming it
    let mut peek_buf = [0u8; 1];
    let n = stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Err(anyhow::anyhow!("connection closed before data"));
    }

    if peek_buf[0] == 0x05 {
        // SOCKS5
        socks::run_socks_single(stream, peer, conn_manager, auth).await
    } else {
        // HTTP
        http::run_http_single(stream, peer, conn_manager, auth).await
    }
}
