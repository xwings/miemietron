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
    grpc_opts: Option<GrpcOpts>,
    h2_opts: Option<H2Opts>,
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

        let connect_opts = ConnectOpts::from_proxy_config(config);

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
        let alpn = match self.network.as_str() {
            "ws" => vec!["http/1.1".to_string()],
            "grpc" | "h2" => vec!["h2".to_string()],
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
        .context("Trojan Reality: invalid configuration")?;

        Ok(Some(config))
    }

    /// The security + transport chain this config asks for.
    fn transport_spec(&self) -> Result<TransportSpec> {
        Ok(TransportSpec {
            label: "Trojan",
            security: self.security_for()?,
            transport: stack::transport_kind(
                &self.network,
                &self.sni,
                self.ws_opts.as_ref(),
                self.grpc_opts.as_ref(),
                self.h2_opts.as_ref(),
                // Trojan has no XHTTP transport in mihomo.
                None,
            )?,
        })
    }

    /// Reality or TLS, and the ALPN the transport dictates. Trojan has no
    /// `tls:` option — the protocol mandates TLS, so there is no plain arm.
    fn security_for(&self) -> Result<SecuritySpec> {
        if let Some(reality_config) = self.build_reality_config()? {
            debug!("Trojan [{}]: using Reality transport", self.name);
            return Ok(SecuritySpec::Reality(reality_config));
        }

        let base = stack::tls_options(
            &self.sni,
            self.skip_cert_verify,
            &self.alpn,
            self.fingerprint.as_deref(),
        );
        Ok(SecuritySpec::Tls(match self.network.as_str() {
            // mihomo compat: trojan.go:95-97 — WS uses DefaultWebsocketALPN
            // (["http/1.1"]) unless the config sets an explicit `alpn`. Unlike
            // VMess/VLESS, an explicit `alpn` is *not* overridden here.
            "ws" if self.alpn.is_empty() => base.with_alpn(vec!["http/1.1".to_string()]),
            "ws" => base,
            // gRPC and H2 require ALPN h2, config `alpn` ignored.
            "grpc" | "h2" => base.with_alpn(vec!["h2".to_string()]),
            _ => base,
        }))
    }
}

#[async_trait]
impl OutboundHandler for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        // mihomo compat: AdapterType.String() == "Trojan" (adapters.go:206).
        "Trojan"
    }

    fn supports_udp(&self) -> bool {
        // UDP relay (connect_datagram) is not yet implemented for Trojan; this
        // flag only mirrors config, so requesting UDP errors at runtime.
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let tcp_stream = self.dial_server(dns).await?;

        let stream = stack::wrap_transport(tcp_stream, self.transport_spec()?).await?;
        let header = encode_request(&self.password_hash, CMD_TCP, target);
        Ok(Box::new(TrojanStream::new(stream, header)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ALPN a given `network` + `alpn` combination ends up sending. Trojan
    /// has no `tls:` option, so there is always a TLS layer.
    fn effective_alpn(network: &str, alpn: &str) -> Vec<String> {
        let yaml = format!(
            r#"
name: test
type: trojan
server: proxy.example.com
port: 443
password: secret
network: {network}
alpn: {alpn}
"#
        );
        let config: ProxyConfig = serde_yaml::from_str(&yaml).unwrap();
        match TrojanOutbound::new(&config)
            .unwrap()
            .security_for()
            .unwrap()
        {
            SecuritySpec::Tls(opts) => opts.alpn,
            SecuritySpec::None => panic!("Trojan always uses TLS"),
            SecuritySpec::Reality(_) => panic!("no reality-opts in this config"),
        }
    }

    #[test]
    fn ws_defaults_to_http11_only_when_alpn_is_unset() {
        // mihomo compat: trojan.go:95-97 — DefaultWebsocketALPN, but an
        // explicit `alpn` wins. This is where Trojan differs from VMess/VLESS,
        // which override the config unconditionally.
        assert_eq!(effective_alpn("ws", "[]"), vec!["http/1.1".to_string()]);
        assert_eq!(
            effective_alpn("ws", "[h2, http/1.1]"),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    #[test]
    fn grpc_and_h2_force_h2_alpn() {
        for network in ["grpc", "h2"] {
            assert_eq!(
                effective_alpn(network, "[http/1.1]"),
                vec!["h2".to_string()],
                "network {network}"
            );
        }
    }

    #[test]
    fn tcp_keeps_the_config_alpn() {
        assert_eq!(
            effective_alpn("tcp", "[h2, http/1.1]"),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
        assert!(effective_alpn("tcp", "[]").is_empty());
    }

    #[test]
    fn reality_takes_precedence_over_tls() {
        let yaml = r#"
name: test
type: trojan
server: proxy.example.com
port: 443
password: secret
network: grpc
client-fingerprint: chrome
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 01020304
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let outbound = TrojanOutbound::new(&config).unwrap();
        assert!(matches!(
            outbound.security_for().unwrap(),
            SecuritySpec::Reality(_)
        ));
    }
}
