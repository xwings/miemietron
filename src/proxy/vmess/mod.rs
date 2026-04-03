pub mod crypto;
pub mod header;

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::common::addr::Address;
use crate::config::proxy::{ProxyConfig, WsOpts};
use crate::dns::DnsResolver;
use crate::proxy::{OutboundHandler, ProxyStream};
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};
use crate::transport::ws::{self, WsOptions};

use crypto::VmessStream;
use header::{encode_request_header, parse_uuid, VmessSecurity, CMD_TCP};

/// VMess outbound proxy handler.
///
/// Supports alterId=0 (AEAD mode) which is the standard for modern VMess
/// deployments. Legacy non-AEAD mode (alterId > 0) is not supported and
/// will log a warning, falling back to AEAD mode.
pub struct VmessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: [u8; 16],
    security: VmessSecurity,
    tls: bool,
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    fingerprint: Option<String>,
    network: String,
    ws_opts: Option<WsOpts>,
    udp: bool,
    connect_opts: ConnectOpts,
}

impl VmessOutbound {
    /// Create a new VMess outbound handler from proxy config.
    pub fn new(config: &ProxyConfig) -> Result<Self> {
        let server = config.server.clone().context("VMess: missing 'server'")?;
        let port = config.port.context("VMess: missing 'port'")?;
        let uuid_str = config.uuid.as_deref().context("VMess: missing 'uuid'")?;
        let uuid =
            parse_uuid(uuid_str).map_err(|e| anyhow::anyhow!("VMess: invalid UUID: {}", e))?;

        // Check alterId -- we only support 0 (AEAD mode).
        let alter_id = config.alter_id.unwrap_or(0);
        if alter_id != 0 {
            warn!(
                "VMess [{}]: alterId={} is not supported (only 0/AEAD mode). \
                 Falling back to AEAD mode.",
                config.name, alter_id
            );
        }

        let security = VmessSecurity::from_str(config.cipher.as_deref().unwrap_or("auto"));

        let tls = config.tls.unwrap_or(false);
        let sni = config
            .sni
            .clone()
            .or_else(|| config.servername.clone())
            .unwrap_or_else(|| server.clone());
        let skip_cert_verify = config.skip_cert_verify.unwrap_or(false);
        let alpn = config.alpn.clone().unwrap_or_default();
        let fingerprint = config
            .client_fingerprint
            .clone()
            .or_else(|| config.fingerprint.clone());
        let network = config.network.clone().unwrap_or_else(|| "tcp".to_string());

        let connect_opts = ConnectOpts {
            interface: config.interface_name.clone(),
            routing_mark: config.routing_mark,
            tfo: config.tfo.unwrap_or(false),
            mptcp: config.mptcp.unwrap_or(false),
        };

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            uuid,
            security,
            tls,
            sni,
            skip_cert_verify,
            alpn,
            fingerprint,
            network,
            ws_opts: config.ws_opts.clone(),
            udp: config.udp.unwrap_or(true),
            connect_opts,
        })
    }

    /// Resolve the proxy server address and open a TCP connection.
    async fn dial_server(&self, dns: &DnsResolver) -> Result<TcpStream> {
        let ip = dns.query_upstream(&self.server).await?;
        let addr = SocketAddr::new(ip, self.port);
        debug!(
            "VMess [{}]: connecting to {}:{}",
            self.name, self.server, self.port
        );
        let stream = tcp::connect(addr, &self.connect_opts).await?;
        Ok(stream)
    }

    /// Build TLS options.
    fn tls_options(&self) -> TlsOptions {
        TlsOptions {
            sni: self.sni.clone(),
            skip_cert_verify: self.skip_cert_verify,
            alpn: self.alpn.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }

    /// Build WebSocket options from config.
    fn build_ws_options(&self) -> WsOptions {
        let mut ws_options = WsOptions {
            host: self.sni.clone(),
            path: "/".to_string(),
            headers: Vec::new(),
        };

        if let Some(ref opts) = self.ws_opts {
            if let Some(ref path) = opts.path {
                ws_options.path = path.clone();
            }
            for (key, value) in &opts.headers {
                ws_options.headers.push((key.clone(), value.clone()));
                if key.to_lowercase() == "host" {
                    ws_options.host = value.clone();
                }
            }
        }

        ws_options
    }

    /// Encode the VMess request header and wrap a transport stream into
    /// an encrypted VmessStream.
    fn wrap_vmess<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
        &self,
        transport: T,
        target: &Address,
    ) -> Box<dyn ProxyStream> {
        let result = encode_request_header(&self.uuid, CMD_TCP, self.security, target);
        let vmess_stream = VmessStream::new(
            transport,
            result.header_bytes,
            result.body_key,
            result.body_iv,
            result.response_auth,
            result.security,
        );
        Box::new(vmess_stream)
    }
}

#[async_trait]
impl OutboundHandler for VmessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "vmess"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        // Step 1: TCP connect to the VMess server.
        let tcp_stream = self.dial_server(dns).await?;

        match self.network.as_str() {
            "ws" => {
                // WebSocket transport (optionally over TLS).
                if self.tls {
                    let tls_opts = self.tls_options();
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VMess: TLS handshake failed")?;

                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(tls_stream, &ws_opts)
                        .await
                        .context("VMess: WebSocket upgrade failed")?;

                    Ok(self.wrap_vmess(ws_stream, target))
                } else {
                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(tcp_stream, &ws_opts)
                        .await
                        .context("VMess: WebSocket upgrade failed")?;

                    Ok(self.wrap_vmess(ws_stream, target))
                }
            }
            _ => {
                // Plain TCP or TLS-only transport.
                if self.tls {
                    let tls_opts = self.tls_options();
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VMess: TLS handshake failed")?;

                    Ok(self.wrap_vmess(tls_stream, target))
                } else {
                    Ok(self.wrap_vmess(tcp_stream, target))
                }
            }
        }
    }
}
