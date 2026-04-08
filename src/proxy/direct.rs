use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tracing::debug;

use super::{OutboundHandler, OutboundPacketConn, ProxyStream};
use crate::common::addr::Address;
use crate::dns::DnsResolver;
use crate::transport::tcp::{self, ConnectOpts};

/// Direct outbound: connect directly to the destination.
///
/// Uses `tcp::connect` with SO_MARK so that outgoing packets bypass the
/// TUN/nftables redirect rules and use the correct routing table.
pub struct DirectOutbound {
    pub routing_mark: Option<u32>,
}

impl DirectOutbound {
    pub fn new(routing_mark: Option<u32>) -> Self {
        Self { routing_mark }
    }
}

#[async_trait]
impl OutboundHandler for DirectOutbound {
    fn name(&self) -> &str {
        "DIRECT"
    }

    fn proto(&self) -> &str {
        "Direct"
    }

    fn supports_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let addr = match target {
            Address::Ip(sockaddr) => *sockaddr,
            Address::Domain(domain, port) => {
                let ip = dns.query_upstream(domain).await?;
                std::net::SocketAddr::new(ip, *port)
            }
        };

        let opts = ConnectOpts {
            routing_mark: self.routing_mark,
            ..Default::default()
        };
        let stream = tcp::connect(addr, &opts).await?;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        _target: &Address,
        dns: Arc<DnsResolver>,
    ) -> Result<Box<dyn OutboundPacketConn>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // mihomo compat: only set SO_MARK when routing-mark is configured.
        // When not configured, GID 65534 (via OpenClash procd) handles bypass.
        if let Some(mark) = self.routing_mark {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
            }
        }

        debug!("DIRECT: created UDP packet conn (mark={:?})", self.routing_mark);
        Ok(Box::new(DirectPacketConn { socket, dns }))
    }
}

/// Direct UDP packet connection — wraps a plain UdpSocket with DNS resolution.
pub struct DirectPacketConn {
    socket: UdpSocket,
    dns: Arc<DnsResolver>,
}

#[async_trait]
impl OutboundPacketConn for DirectPacketConn {
    async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize> {
        let addr = match target {
            Address::Ip(sockaddr) => *sockaddr,
            Address::Domain(domain, port) => {
                let ip = self.dns.query_upstream(domain).await?;
                std::net::SocketAddr::new(ip, *port)
            }
        };
        let n = self.socket.send_to(data, addr).await?;
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let (n, addr) = self.socket.recv_from(buf).await?;
        Ok((n, Address::Ip(addr)))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Reject outbound: immediately returns an error.
pub struct RejectOutbound;

#[async_trait]
impl OutboundHandler for RejectOutbound {
    fn name(&self) -> &str {
        "REJECT"
    }

    fn proto(&self) -> &str {
        "Reject"
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        _target: &Address,
        _dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        Err(anyhow::anyhow!("connection rejected"))
    }
}

/// RejectDrop: silently drops the connection.
pub struct RejectDropOutbound;

#[async_trait]
impl OutboundHandler for RejectDropOutbound {
    fn name(&self) -> &str {
        "REJECT-DROP"
    }

    fn proto(&self) -> &str {
        "RejectDrop"
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        _target: &Address,
        _dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        // Wait briefly then drop — don't hold fds for 24 hours
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        Err(anyhow::anyhow!("connection dropped"))
    }
}

/// Placeholder outbound for protocols not yet implemented.
/// Logs a warning and falls back to DIRECT.
pub struct PlaceholderOutbound {
    proxy_name: String,
    proto: String,
    routing_mark: Option<u32>,
}

impl PlaceholderOutbound {
    pub fn new(name: String, proto: &str, routing_mark: Option<u32>) -> Self {
        Self {
            proxy_name: name,
            proto: proto.to_string(),
            routing_mark,
        }
    }
}

#[async_trait]
impl OutboundHandler for PlaceholderOutbound {
    fn name(&self) -> &str {
        &self.proxy_name
    }

    fn proto(&self) -> &str {
        &self.proto
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        tracing::warn!(
            "Proxy {} ({}) not implemented, falling back to DIRECT",
            self.proxy_name,
            self.proto
        );
        DirectOutbound::new(self.routing_mark).connect_stream(target, dns).await
    }
}
