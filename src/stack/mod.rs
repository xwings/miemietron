// Network stack abstraction.
//
// The "system" stack uses the kernel's TCP/IP via iptables REDIRECT + SO_ORIGINAL_DST.
// This avoids the complexity of a full userspace TCP stack while still processing
// all traffic through the TUN device.

pub mod system;

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
