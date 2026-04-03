pub mod header;

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::addr::Address;
use crate::config::proxy::{ProxyConfig, RealityOpts, WsOpts};
use crate::dns::DnsResolver;
use crate::proxy::{OutboundHandler, ProxyStream};
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};
use crate::transport::ws::{self, WsOptions};

use header::{encode_request, parse_uuid, VlessStream, CMD_TCP};

/// VLESS outbound proxy handler.
pub struct VlessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: [u8; 16],
    flow: Option<String>,
    tls: bool,
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    fingerprint: Option<String>,
    network: String,
    ws_opts: Option<WsOpts>,
    reality_opts: Option<RealityOpts>,
    udp: bool,
    connect_opts: ConnectOpts,
}

impl VlessOutbound {
    /// Create a new VLESS outbound handler from proxy config.
    pub fn new(config: &ProxyConfig) -> Result<Self> {
        let server = config.server.clone().context("VLESS: missing 'server'")?;
        let port = config.port.context("VLESS: missing 'port'")?;
        let uuid_str = config.uuid.as_deref().context("VLESS: missing 'uuid'")?;
        let uuid =
            parse_uuid(uuid_str).map_err(|e| anyhow::anyhow!("VLESS: invalid UUID: {}", e))?;

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
            flow: config.flow.clone(),
            tls,
            sni,
            skip_cert_verify,
            alpn,
            fingerprint,
            network,
            ws_opts: config.ws_opts.clone(),
            reality_opts: config.reality_opts.clone(),
            udp: config.udp.unwrap_or(true),
            connect_opts,
        })
    }

    /// Resolve the proxy server address and open a TCP connection.
    async fn dial_server(&self, dns: &DnsResolver) -> Result<TcpStream> {
        let ip = dns.query_upstream(&self.server).await?;
        let addr = SocketAddr::new(ip, self.port);
        debug!(
            "VLESS [{}]: connecting to {}:{}",
            self.name, self.server, self.port
        );
        let stream = tcp::connect(addr, &self.connect_opts).await?;
        Ok(stream)
    }
}

#[async_trait]
impl OutboundHandler for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "vless"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        // Step 1: TCP connect to the VLESS server.
        let tcp_stream = self.dial_server(dns).await?;

        // Step 2: Apply transport layers based on config.
        match self.network.as_str() {
            "ws" => {
                // WebSocket transport (optionally over TLS).
                if self.tls {
                    let tls_opts = TlsOptions {
                        sni: self.sni.clone(),
                        skip_cert_verify: self.skip_cert_verify,
                        alpn: self.alpn.clone(),
                        fingerprint: self.fingerprint.clone(),
                    };
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VLESS: TLS handshake failed")?;

                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(tls_stream, &ws_opts)
                        .await
                        .context("VLESS: WebSocket upgrade failed")?;

                    let header = encode_request(&self.uuid, CMD_TCP, target);
                    let vless_stream = VlessStream::new(ws_stream, header);
                    Ok(Box::new(vless_stream))
                } else {
                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(tcp_stream, &ws_opts)
                        .await
                        .context("VLESS: WebSocket upgrade failed")?;

                    let header = encode_request(&self.uuid, CMD_TCP, target);
                    let vless_stream = VlessStream::new(ws_stream, header);
                    Ok(Box::new(vless_stream))
                }
            }
            _ => {
                // Plain TCP or TLS-only transport.
                if self.tls {
                    let tls_opts = TlsOptions {
                        sni: self.sni.clone(),
                        skip_cert_verify: self.skip_cert_verify,
                        alpn: self.alpn.clone(),
                        fingerprint: self.fingerprint.clone(),
                    };
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VLESS: TLS handshake failed")?;

                    let header = encode_request(&self.uuid, CMD_TCP, target);
                    let vless_stream = VlessStream::new(tls_stream, header);
                    Ok(Box::new(vless_stream))
                } else {
                    let header = encode_request(&self.uuid, CMD_TCP, target);
                    let vless_stream = VlessStream::new(tcp_stream, header);
                    Ok(Box::new(vless_stream))
                }
            }
        }
    }
}

impl VlessOutbound {
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
}
