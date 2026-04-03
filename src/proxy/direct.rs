use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::{OutboundHandler, ProxyStream};
use crate::common::addr::Address;
use crate::dns::DnsResolver;

/// Direct outbound: connect directly to the destination.
pub struct DirectOutbound;

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

        let stream = TcpStream::connect(addr).await?;
        Ok(Box::new(stream))
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
        // Wait indefinitely to simulate a dropped connection
        tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
        Err(anyhow::anyhow!("connection dropped"))
    }
}

/// Placeholder outbound for protocols not yet implemented.
/// Logs a warning and falls back to DIRECT.
pub struct PlaceholderOutbound {
    proxy_name: String,
    proto: String,
}

impl PlaceholderOutbound {
    pub fn new(name: String, proto: &str) -> Self {
        Self {
            proxy_name: name,
            proto: proto.to_string(),
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
        DirectOutbound.connect_stream(target, dns).await
    }
}
