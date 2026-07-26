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
use crate::transport::reality::RealityConfig;
use crate::transport::stack::{self, SecuritySpec, TransportSpec};
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::xhttp::XHttpConfig;

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

        let stream = stack::wrap_transport(tcp_stream, self.transport_spec()?).await?;
        Ok(Box::new(VlessStream::new(stream, header)))
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

    /// The security + transport chain this config asks for.
    fn transport_spec(&self) -> Result<TransportSpec> {
        Ok(TransportSpec {
            label: "VLESS",
            security: self.security_for()?,
            transport: stack::transport_kind(
                &self.network,
                &self.sni,
                self.ws_opts.as_ref(),
                self.grpc_opts.as_ref(),
                self.h2_opts.as_ref(),
                self.xhttp_config.as_ref(),
            )?,
        })
    }

    /// Reality, TLS, or nothing — and, for TLS, the ALPN the transport dictates.
    fn security_for(&self) -> Result<SecuritySpec> {
        if let Some(reality_config) = self.build_reality_config()? {
            debug!("VLESS [{}]: using Reality transport", self.name);
            return Ok(SecuritySpec::Reality(reality_config));
        }

        // mihomo compat: every transport routes its TLS through
        // `streamTLSConn` (`vless.go:267`), whose whole body is inside
        // `if v.option.TLS` — and gRPC's `gun.Config` gets a nil `tlsConfig`
        // unless `option.TLS` (`vless.go` NewVless). So `tls: false` means
        // plain TCP / ws / h2c / gRPC-over-h2c, never an implicit TLS layer.
        if !self.tls {
            return Ok(SecuritySpec::None);
        }

        let base = stack::tls_options(
            &self.sni,
            self.skip_cert_verify,
            &self.alpn,
            self.fingerprint.as_deref(),
        );
        Ok(SecuritySpec::Tls(match self.network.as_str() {
            // mihomo compat: vless.go:165 forces ALPN http/1.1 for WebSocket
            // regardless of the config's `alpn` — a WS upgrade cannot run over
            // an h2/h3-negotiated TLS conn.
            "ws" => base.with_alpn(vec!["http/1.1".to_string()]),
            // mihomo compat: `streamTLSConn(_, isH2: true)` overrides NextProtos
            // with ["h2"] for h2, and NewVless's gun config hardcodes the same
            // for gRPC. XHTTP: mihomo NewTransport forces h2 unless ALPN is
            // exactly [http/1.1] or [h3], even when the config lists both h2
            // and http/1.1 (both of those exact cases are rejected in `new`).
            "grpc" | "h2" | "xhttp" => base.with_alpn(vec!["h2".to_string()]),
            _ => base,
        }))
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

    /// The ALPN a given `network` + `tls` + `alpn` combination ends up sending,
    /// or `None` when no TLS layer is used at all.
    fn effective_alpn(network: &str, tls: bool, alpn: &str) -> Option<Vec<String>> {
        let yaml = format!(
            r#"
name: test
type: vless
server: proxy.example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
tls: {tls}
network: {network}
alpn: {alpn}
xhttp-opts:
  host: edge.example.com
  mode: auto
"#
        );
        let config: ProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        match VlessOutbound::new(&config).unwrap().security_for().unwrap() {
            SecuritySpec::Tls(opts) => Some(opts.alpn),
            SecuritySpec::None => None,
            SecuritySpec::Reality(_) => panic!("no reality-opts in this config"),
        }
    }

    #[test]
    fn ws_forces_http11_alpn_over_the_config() {
        // mihomo compat: vless.go:165.
        assert_eq!(
            effective_alpn("ws", true, "[h2, http/1.1]"),
            Some(vec!["http/1.1".to_string()])
        );
    }

    #[test]
    fn grpc_h2_and_xhttp_force_h2_alpn() {
        for network in ["grpc", "h2"] {
            assert_eq!(
                effective_alpn(network, true, "[http/1.1]"),
                Some(vec!["h2".to_string()]),
                "network {network}"
            );
        }
        // An exactly-[http/1.1] xhttp config is rejected in `new`, so the
        // interesting case is the mixed list mihomo still resolves to h2.
        assert_eq!(
            effective_alpn("xhttp", true, "[h2, http/1.1]"),
            Some(vec!["h2".to_string()])
        );
    }

    #[test]
    fn tcp_keeps_the_config_alpn() {
        assert_eq!(
            effective_alpn("tcp", true, "[h2, http/1.1]"),
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
    }

    #[test]
    fn tls_false_adds_no_security_layer_for_any_network() {
        // mihomo compat: `streamTLSConn` (vless.go:267) is a no-op unless
        // `option.TLS`, and NewVless leaves gun's tlsConfig nil — so gRPC and
        // H2 run over h2c, they do not silently gain TLS.
        for network in ["tcp", "ws", "grpc", "h2", "xhttp"] {
            assert_eq!(
                effective_alpn(network, false, "[]"),
                None,
                "network {network}"
            );
        }
    }

    #[test]
    fn reality_takes_precedence_over_tls() {
        let yaml = r#"
name: test
type: vless
server: proxy.example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
tls: true
network: grpc
client-fingerprint: chrome
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 01020304
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let outbound = VlessOutbound::new(&config).unwrap();
        assert!(matches!(
            outbound.security_for().unwrap(),
            SecuritySpec::Reality(_)
        ));
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
