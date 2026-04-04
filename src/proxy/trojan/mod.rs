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
use crate::transport::fingerprint::TlsFingerprint;
use crate::transport::reality::{self, RealityConfig};
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};
use crate::transport::ws::{self, WsOptions};

use header::{encode_request, hex_sha224, TrojanStream, CMD_TCP};

/// Trojan outbound proxy handler.
pub struct TrojanOutbound {
    name: String,
    server: String,
    port: u16,
    password_hash: String,
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

impl TrojanOutbound {
    /// Create a new Trojan outbound handler from proxy config.
    pub fn new(config: &ProxyConfig) -> Result<Self> {
        let server = config.server.clone().context("Trojan: missing 'server'")?;
        let port = config.port.context("Trojan: missing 'port'")?;
        let password = config
            .password
            .as_deref()
            .context("Trojan: missing 'password'")?;

        let password_hash = hex_sha224(password);

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
            password_hash,
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
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let addr = SocketAddr::new(ip, self.port);
        debug!(
            "Trojan [{}]: connecting to {}:{}",
            self.name, self.server, self.port
        );
        let stream = tcp::connect(addr, &self.connect_opts).await?;
        Ok(stream)
    }

    /// Build a [`RealityConfig`] from the proxy config's `reality_opts`,
    /// if present.  Returns `Ok(None)` when Reality is not configured.
    fn build_reality_config(&self) -> Result<Option<RealityConfig>> {
        let opts = match self.reality_opts {
            Some(ref o) => o,
            None => return Ok(None),
        };

        let public_key = opts
            .public_key
            .as_deref()
            .context("Trojan Reality: missing 'public-key'")?;
        let short_id = opts.short_id.as_deref().unwrap_or("");
        let fp = TlsFingerprint::from_str_opt(self.fingerprint.as_deref());

        let config = RealityConfig::from_opts(public_key, short_id, self.sni.clone(), fp)
            .context("Trojan Reality: invalid configuration")?;

        Ok(Some(config))
    }

    /// Build TLS options. Trojan always requires TLS.
    fn tls_options(&self) -> TlsOptions {
        TlsOptions {
            sni: self.sni.clone(),
            skip_cert_verify: self.skip_cert_verify,
            alpn: self.alpn.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }

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

#[async_trait]
impl OutboundHandler for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "trojan"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        // Step 1: TCP connect to the Trojan server.
        let tcp_stream = self.dial_server(dns).await?;

        // Step 2: Check if Reality transport is configured.
        if let Some(reality_config) = self.build_reality_config()? {
            debug!("Trojan [{}]: using Reality transport", self.name);

            let reality_stream = reality::wrap_reality(tcp_stream, &reality_config)
                .await
                .context("Trojan: Reality handshake failed")?;

            match self.network.as_str() {
                "ws" => {
                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(reality_stream, &ws_opts)
                        .await
                        .context("Trojan: WebSocket upgrade over Reality failed")?;

                    let header = encode_request(&self.password_hash, CMD_TCP, target);
                    let trojan_stream = TrojanStream::new(ws_stream, header);
                    Ok(Box::new(trojan_stream))
                }
                _ => {
                    let header = encode_request(&self.password_hash, CMD_TCP, target);
                    let trojan_stream = TrojanStream::new(reality_stream, header);
                    Ok(Box::new(trojan_stream))
                }
            }
        } else {
            // Standard TLS transport (Trojan always requires TLS).
            let tls_opts = self.tls_options();
            let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                .await
                .context("Trojan: TLS handshake failed")?;

            match self.network.as_str() {
                "ws" => {
                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(tls_stream, &ws_opts)
                        .await
                        .context("Trojan: WebSocket upgrade failed")?;

                    let header = encode_request(&self.password_hash, CMD_TCP, target);
                    let trojan_stream = TrojanStream::new(ws_stream, header);
                    Ok(Box::new(trojan_stream))
                }
                _ => {
                    // TLS only (standard Trojan).
                    let header = encode_request(&self.password_hash, CMD_TCP, target);
                    let trojan_stream = TrojanStream::new(tls_stream, header);
                    Ok(Box::new(trojan_stream))
                }
            }
        }
    }
}
