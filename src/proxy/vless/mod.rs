pub mod header;
pub mod vision;

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::addr::Address;
use crate::config::proxy::{GrpcOpts, H2Opts, ProxyConfig, RealityOpts, WsOpts};
use crate::dns::DnsResolver;
use crate::proxy::{OutboundHandler, ProxyStream};
use crate::transport::fingerprint::TlsFingerprint;
use crate::transport::grpc;
use crate::transport::h2_transport;
use crate::transport::reality::{self, RealityConfig};
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};
use crate::transport::ws::{self, WsOptions};

use header::{encode_request_with_flow, parse_uuid, VlessStream, CMD_TCP};

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
    grpc_opts: Option<GrpcOpts>,
    h2_opts: Option<H2Opts>,
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
        let uuid = parse_uuid(uuid_str).map_err(|e| anyhow::anyhow!("VLESS: invalid UUID: {e}"))?;

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

        let connect_opts = ConnectOpts::from_proxy_config(config);

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
            grpc_opts: config.grpc_opts.clone(),
            h2_opts: config.h2_opts.clone(),
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
        let tcp_stream = self.dial_server(dns).await?;

        // Check if Reality transport is configured.
        if let Some(reality_config) = self.build_reality_config()? {
            // Reality transport — perform the Reality handshake which
            // includes TLS with camouflage SNI + x25519 auth, then
            // layer the VLESS protocol on top.
            debug!("VLESS [{}]: using Reality transport", self.name);

            match self.network.as_str() {
                "ws" => {
                    let reality_stream = reality::wrap_reality(tcp_stream, &reality_config)
                        .await
                        .context("VLESS: Reality handshake failed")?;

                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(reality_stream, &ws_opts)
                        .await
                        .context("VLESS: WebSocket upgrade over Reality failed")?;

                    let header = self.build_header(CMD_TCP, target);
                    let vless_stream = VlessStream::new(ws_stream, header);
                    Ok(Box::new(vless_stream))
                }
                "grpc" => {
                    let reality_stream = reality::wrap_reality(tcp_stream, &reality_config)
                        .await
                        .context("VLESS: Reality handshake failed")?;

                    let service_name = self.grpc_service_name();
                    let grpc_stream = grpc::connect_grpc(reality_stream, &service_name, &self.sni)
                        .await
                        .context("VLESS: gRPC connect over Reality failed")?;

                    let header = self.build_header(CMD_TCP, target);
                    let vless_stream = VlessStream::new(grpc_stream, header);
                    Ok(Box::new(vless_stream))
                }
                "h2" => {
                    let reality_stream = reality::wrap_reality(tcp_stream, &reality_config)
                        .await
                        .context("VLESS: Reality handshake failed")?;

                    let (host, path) = self.h2_host_path();
                    let h2_stream = h2_transport::connect_h2(reality_stream, &host, &path)
                        .await
                        .context("VLESS: H2 connect over Reality failed")?;

                    let header = self.build_header(CMD_TCP, target);
                    let vless_stream = VlessStream::new(h2_stream, header);
                    Ok(Box::new(vless_stream))
                }
                _ => {
                    let reality_stream = reality::wrap_reality(tcp_stream, &reality_config)
                        .await
                        .context("VLESS: Reality handshake failed")?;

                    let header = self.build_header(CMD_TCP, target);
                    let vless_stream = VlessStream::new(reality_stream, header);
                    Ok(Box::new(vless_stream))
                }
            }
        } else {
            // Standard transport (TLS or plain TCP).
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

                        let header = self.build_header(CMD_TCP, target);
                        let vless_stream = VlessStream::new(ws_stream, header);
                        Ok(Box::new(vless_stream))
                    } else {
                        let ws_opts = self.build_ws_options();
                        let ws_stream = ws::wrap_ws(tcp_stream, &ws_opts)
                            .await
                            .context("VLESS: WebSocket upgrade failed")?;

                        let header = self.build_header(CMD_TCP, target);
                        let vless_stream = VlessStream::new(ws_stream, header);
                        Ok(Box::new(vless_stream))
                    }
                }
                "grpc" => {
                    // gRPC requires TLS with ALPN=h2
                    let tls_opts = TlsOptions {
                        sni: self.sni.clone(),
                        skip_cert_verify: self.skip_cert_verify,
                        alpn: vec!["h2".to_string()],
                        fingerprint: self.fingerprint.clone(),
                    };
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VLESS: TLS handshake for gRPC failed")?;

                    let service_name = self.grpc_service_name();
                    let grpc_stream = grpc::connect_grpc(tls_stream, &service_name, &self.sni)
                        .await
                        .context("VLESS: gRPC connect failed")?;

                    let header = self.build_header(CMD_TCP, target);
                    let vless_stream = VlessStream::new(grpc_stream, header);
                    Ok(Box::new(vless_stream))
                }
                "h2" => {
                    // H2 requires TLS with ALPN=h2
                    let tls_opts = TlsOptions {
                        sni: self.sni.clone(),
                        skip_cert_verify: self.skip_cert_verify,
                        alpn: vec!["h2".to_string()],
                        fingerprint: self.fingerprint.clone(),
                    };
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VLESS: TLS handshake for H2 failed")?;

                    let (host, path) = self.h2_host_path();
                    let h2_stream = h2_transport::connect_h2(tls_stream, &host, &path)
                        .await
                        .context("VLESS: H2 connect failed")?;

                    let header = self.build_header(CMD_TCP, target);
                    let vless_stream = VlessStream::new(h2_stream, header);
                    Ok(Box::new(vless_stream))
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

                        let header = self.build_header(CMD_TCP, target);
                        let vless_stream = VlessStream::new(tls_stream, header);
                        Ok(Box::new(vless_stream))
                    } else {
                        let header = self.build_header(CMD_TCP, target);
                        let vless_stream = VlessStream::new(tcp_stream, header);
                        Ok(Box::new(vless_stream))
                    }
                }
            }
        }
    }
}

impl VlessOutbound {
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
            .context("VLESS Reality: missing 'public-key'")?;
        let short_id = opts.short_id.as_deref().unwrap_or("");
        let fp = TlsFingerprint::from_str_opt(self.fingerprint.as_deref());

        let config = RealityConfig::from_opts(public_key, short_id, self.sni.clone(), fp)
            .context("VLESS Reality: invalid configuration")?;

        Ok(Some(config))
    }

    /// Build the VLESS request header, including the flow addon if configured.
    fn build_header(&self, cmd: u8, target: &Address) -> Vec<u8> {
        encode_request_with_flow(&self.uuid, cmd, target, self.flow.as_deref())
    }

    fn grpc_service_name(&self) -> String {
        self.grpc_opts
            .as_ref()
            .and_then(|o| o.grpc_service_name.clone())
            .unwrap_or_else(|| "GunService".to_string())
    }

    fn h2_host_path(&self) -> (String, String) {
        let host = self
            .h2_opts
            .as_ref()
            .and_then(|o| o.host.first().cloned())
            .unwrap_or_else(|| self.sni.clone());
        let path = self
            .h2_opts
            .as_ref()
            .and_then(|o| o.path.clone())
            .unwrap_or_else(|| "/".to_string());
        (host, path)
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
