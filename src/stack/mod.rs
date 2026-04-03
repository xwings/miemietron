// Network stack abstraction.
// Phase 1: stub
// Phase 2+: system stack (kernel TCP/IP) and smoltcp userspace stack.

use anyhow::Result;
use std::net::SocketAddr;

/// Trait for the network stack that processes TUN packets.
#[async_trait::async_trait]
pub trait NetworkStack: Send + Sync {
    /// Accept the next TCP connection from the TUN.
    async fn accept_tcp(&self) -> Result<(Box<dyn TunStream>, SocketAddr, SocketAddr)>;
}

pub trait TunStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TunStream for T {}
