//! Snell v3 outbound proxy handler.
//!
//! Snell is a simple encrypted proxy protocol. V3 uses AEAD encryption
//! with a custom obfuscation layer.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use super::{OutboundHandler, ProxyStream};
use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::transport::tcp::{self, ConnectOpts};

// Snell protocol constants
#[allow(dead_code)]
const SNELL_VERSION: u8 = 3;
const CMD_CONNECT: u8 = 0x01;

#[allow(dead_code)]
pub struct SnellOutbound {
    name: String,
    server: String,
    port: u16,
    psk: Vec<u8>,
    obfs: Option<String>,
    obfs_host: Option<String>,
    version: u8,
    connect_opts: ConnectOpts,
}

impl SnellOutbound {
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("snell missing server"))?
            .clone();
        let port = config.port.ok_or_else(|| anyhow!("snell missing port"))?;
        let psk = config
            .password
            .as_ref()
            .ok_or_else(|| anyhow!("snell missing psk"))?
            .as_bytes()
            .to_vec();

        let obfs = config
            .extra
            .get("obfs")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let obfs_host = config
            .extra
            .get("obfs-host")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let version = config
            .extra
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as u8;

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            psk,
            obfs,
            obfs_host,
            version,
            connect_opts: ConnectOpts::from_proxy_config(config),
        })
    }

    /// Derive the session key from the PSK using HKDF-like derivation.
    #[allow(dead_code)]
    fn derive_key(&self) -> [u8; 32] {
        let hash = sha2::Sha256::digest(&self.psk);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }
}

#[async_trait]
impl OutboundHandler for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "Snell"
    }

    fn supports_udp(&self) -> bool {
        self.version >= 3
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let addr = std::net::SocketAddr::new(ip, self.port);
        let mut stream = tcp::connect(addr, &self.connect_opts).await?;
        debug!("Snell v{} connected to {}:{}", self.version, self.server, self.port);

        // Build Snell CONNECT request header
        // Format: [version(1)] [cmd(1)] [host_len(1)] [host] [port(2)]
        let (host, port) = match target {
            Address::Domain(h, p) => (h.clone(), *p),
            Address::Ip(a) => (a.ip().to_string(), a.port()),
        };

        let mut header = Vec::with_capacity(4 + host.len());
        header.push(self.version);
        header.push(CMD_CONNECT);
        header.push(host.len() as u8);
        header.extend_from_slice(host.as_bytes());
        header.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&header).await?;
        stream.flush().await?;

        // Read server response (1 byte)
        let mut resp = [0u8; 1];
        stream.read_exact(&mut resp).await?;

        if resp[0] != 0 {
            return Err(anyhow!("Snell CONNECT failed with code: {}", resp[0]));
        }

        debug!("Snell tunnel established to {}:{}", host, port);
        Ok(Box::new(stream))
    }
}
