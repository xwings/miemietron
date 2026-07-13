pub mod header;

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
use crate::transport::xhttp::{self, XHttpConfig};

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
    xhttp_config: Option<XHttpConfig>,
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
        let xhttp_config = if network == "xhttp" {
            if alpn.len() == 1 && alpn[0] == "h3" {
                anyhow::bail!("VLESS XHTTP: HTTP/3 transport is not implemented yet");
            }
            if alpn.len() == 1 && alpn[0] == "http/1.1" {
                anyhow::bail!("VLESS XHTTP: HTTP/1.1 transport is not implemented yet");
            }
            Some(
                XHttpConfig::from_options(
                    config.xhttp_opts.as_ref(),
                    &sni,
                    config.reality_opts.is_some(),
                )
                .context("VLESS XHTTP: invalid configuration")?,
            )
        } else {
            None
        };

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
            xhttp_config,
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
        // mihomo compat: AdapterType.String() == "Vless" (adapters.go).
        "Vless"
    }

    fn supports_udp(&self) -> bool {
        // UDP relay (connect_datagram) is not yet implemented for VLESS; this
        // flag only mirrors config, so requesting UDP errors at runtime.
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let tcp_stream = self.dial_server(dns).await?;
        let header = self.build_header(CMD_TCP, target);

        // Check if Reality transport is configured.
        if let Some(reality_config) = self.build_reality_config()? {
            // Reality transport — perform the Reality handshake which
            // includes TLS with camouflage SNI + x25519 auth, then
            // layer the VLESS protocol on top.
            debug!("VLESS [{}]: using Reality transport", self.name);

            let reality_stream = reality::wrap_reality(tcp_stream, &reality_config)
                .await
                .context("VLESS: Reality handshake failed")?;

            match self.network.as_str() {
                "ws" => {
                    let ws_opts = self.build_ws_options();
                    let ws_stream = ws::wrap_ws(reality_stream, &ws_opts)
                        .await
                        .context("VLESS: WebSocket upgrade over Reality failed")?;

                    Ok(Box::new(VlessStream::new(ws_stream, header)))
                }
                "grpc" => {
                    let service_name = self.grpc_service_name();
                    let grpc_stream = grpc::connect_grpc(reality_stream, &service_name, &self.sni)
                        .await
                        .context("VLESS: gRPC connect over Reality failed")?;

                    Ok(Box::new(VlessStream::new(grpc_stream, header)))
                }
                "h2" => {
                    let (host, path) = self.h2_host_path();
                    let h2_stream = h2_transport::connect_h2(reality_stream, &host, &path)
                        .await
                        .context("VLESS: H2 connect over Reality failed")?;

                    Ok(Box::new(VlessStream::new(h2_stream, header)))
                }
                "xhttp" => {
                    let xhttp_config = self
                        .xhttp_config
                        .clone()
                        .context("VLESS XHTTP: missing normalized configuration")?;
                    let xhttp_stream = xhttp::connect_h2(reality_stream, xhttp_config)
                        .await
                        .context("VLESS XHTTP: HTTP/2 connect over Reality failed")?;
                    Ok(Box::new(VlessStream::new(xhttp_stream, header)))
                }
                _ => Ok(Box::new(VlessStream::new(reality_stream, header))),
            }
        } else {
            // Standard transport (TLS or plain TCP).
            match self.network.as_str() {
                "ws" => {
                    // WebSocket transport (optionally over TLS).
                    if self.tls {
                        // mihomo compat: vless.go:165 forces ALPN http/1.1 for
                        // WebSocket regardless of the config's `alpn` — a WS
                        // upgrade cannot run over an h2/h3-negotiated TLS conn.
                        let tls_opts = self.tls_options().with_alpn(vec!["http/1.1".to_string()]);
                        let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                            .await
                            .context("VLESS: TLS handshake failed")?;

                        let ws_opts = self.build_ws_options();
                        let ws_stream = ws::wrap_ws(tls_stream, &ws_opts)
                            .await
                            .context("VLESS: WebSocket upgrade failed")?;

                        Ok(Box::new(VlessStream::new(ws_stream, header)))
                    } else {
                        let ws_opts = self.build_ws_options();
                        let ws_stream = ws::wrap_ws(tcp_stream, &ws_opts)
                            .await
                            .context("VLESS: WebSocket upgrade failed")?;

                        Ok(Box::new(VlessStream::new(ws_stream, header)))
                    }
                }
                "grpc" => {
                    // gRPC requires TLS with ALPN=h2
                    let tls_opts = self.tls_options().with_alpn(vec!["h2".to_string()]);
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VLESS: TLS handshake for gRPC failed")?;

                    let service_name = self.grpc_service_name();
                    let grpc_stream = grpc::connect_grpc(tls_stream, &service_name, &self.sni)
                        .await
                        .context("VLESS: gRPC connect failed")?;

                    Ok(Box::new(VlessStream::new(grpc_stream, header)))
                }
                "h2" => {
                    // H2 requires TLS with ALPN=h2
                    let tls_opts = self.tls_options().with_alpn(vec!["h2".to_string()]);
                    let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                        .await
                        .context("VLESS: TLS handshake for H2 failed")?;

                    let (host, path) = self.h2_host_path();
                    let h2_stream = h2_transport::connect_h2(tls_stream, &host, &path)
                        .await
                        .context("VLESS: H2 connect failed")?;

                    Ok(Box::new(VlessStream::new(h2_stream, header)))
                }
                "xhttp" => {
                    let xhttp_config = self
                        .xhttp_config
                        .clone()
                        .context("VLESS XHTTP: missing normalized configuration")?;

                    if self.tls {
                        // mihomo NewTransport forces h2 unless ALPN is exactly
                        // [http/1.1] or [h3], even when the config lists both
                        // h2 and http/1.1.
                        let tls_opts = self.tls_options().with_alpn(vec!["h2".to_string()]);
                        let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                            .await
                            .context("VLESS XHTTP: TLS handshake failed")?;
                        let xhttp_stream = xhttp::connect_h2(tls_stream, xhttp_config)
                            .await
                            .context("VLESS XHTTP: HTTP/2 connect failed")?;
                        Ok(Box::new(VlessStream::new(xhttp_stream, header)))
                    } else {
                        let xhttp_stream = xhttp::connect_h2(tcp_stream, xhttp_config)
                            .await
                            .context("VLESS XHTTP: h2c connect failed")?;
                        Ok(Box::new(VlessStream::new(xhttp_stream, header)))
                    }
                }
                _ => {
                    // Plain TCP or TLS-only transport.
                    if self.tls {
                        let tls_opts = self.tls_options();
                        let tls_stream = tls::wrap_tls(tcp_stream, &tls_opts)
                            .await
                            .context("VLESS: TLS handshake failed")?;

                        Ok(Box::new(VlessStream::new(tls_stream, header)))
                    } else {
                        Ok(Box::new(VlessStream::new(tcp_stream, header)))
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
        let alpn = match self.network.as_str() {
            "ws" => vec!["http/1.1".to_string()],
            "grpc" | "h2" | "xhttp" => vec!["h2".to_string()],
            _ if self.alpn.is_empty() => crate::transport::fingerprint::default_alpn_for(fp),
            _ => self.alpn.clone(),
        };

        let config = RealityConfig::from_opts(
            public_key,
            short_id,
            self.sni.clone(),
            fp,
            alpn,
            opts.support_x25519mlkem768,
        )
        .context("VLESS Reality: invalid configuration")?;

        Ok(Some(config))
    }

    /// Build the VLESS request header, including the flow addon if configured.
    fn build_header(&self, cmd: u8, target: &Address) -> Vec<u8> {
        encode_request_with_flow(&self.uuid, cmd, target, self.flow.as_deref())
    }

    /// Build the base TLS options (uses the config's `alpn`; callers override
    /// via `with_alpn` where the transport dictates a specific ALPN).
    fn tls_options(&self) -> TlsOptions {
        TlsOptions {
            sni: self.sni.clone(),
            skip_cert_verify: self.skip_cert_verify,
            alpn: self.alpn.clone(),
            fingerprint: self.fingerprint.clone(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_xhttp(alpn: &str) -> ProxyConfig {
        serde_yaml::from_str(&format!(
            r#"
name: test-xhttp
type: vless
server: proxy.example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
tls: true
network: xhttp
alpn: {alpn}
xhttp-opts:
  host: edge.example.com
  mode: auto
  path: /tunnel
  x-padding-bytes: 100-1000
"#
        ))
        .unwrap()
    }

    #[test]
    fn xhttp_accepts_mihomo_default_h2_selection() {
        let config = parse_xhttp("[h2, http/1.1]");
        let outbound = VlessOutbound::new(&config).unwrap();
        assert!(outbound.xhttp_config.is_some());
    }

    #[test]
    fn xhttp_exact_http1_is_rejected_at_load() {
        let config = parse_xhttp("[http/1.1]");
        let error = VlessOutbound::new(&config).err().unwrap().to_string();
        assert!(error.contains("HTTP/1.1 transport is not implemented"));
    }

    #[test]
    fn xhttp_exact_h3_is_rejected_at_load() {
        let config = parse_xhttp("[h3]");
        let error = VlessOutbound::new(&config).err().unwrap().to_string();
        assert!(error.contains("HTTP/3 transport is not implemented"));
    }

    #[test]
    fn xhttp_with_reality_is_accepted_for_h2() {
        let yaml = r#"
name: test-xhttp-reality
type: vless
server: proxy.example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
tls: true
network: xhttp
client-fingerprint: chrome
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 01020304
xhttp-opts:
  host: edge.example.com
  mode: auto
  path: /tunnel
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let outbound = VlessOutbound::new(&config).unwrap();
        assert!(outbound.xhttp_config.is_some());
    }
}
