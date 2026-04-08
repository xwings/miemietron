// Network stack abstraction.
//
// The "system" stack uses the kernel's TCP/IP via iptables REDIRECT + SO_ORIGINAL_DST.
// The "gvisor" stack uses a user-space TCP/IP stack (smoltcp) to process raw IP packets.
// The "mixed" stack uses gvisor for TCP and system for UDP.

pub mod gvisor;
pub mod system;

use anyhow::Result;
use std::net::SocketAddr;

/// Trait for the network stack that processes TUN packets.
#[allow(dead_code)]
#[async_trait::async_trait]
pub trait NetworkStack: Send + Sync {
    /// Accept the next TCP connection from the TUN.
    async fn accept_tcp(&self) -> Result<(Box<dyn TunStream>, SocketAddr, SocketAddr)>;
}

#[allow(dead_code)]
pub trait TunStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TunStream for T {}
