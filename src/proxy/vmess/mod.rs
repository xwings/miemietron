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
        let uuid = parse_uuid(uuid_str).map_err(|e| anyhow::anyhow!("VMess: invalid UUID: {e}"))?;

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
        let ip = dns.resolve_proxy_server(&self.server).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::ProxyConfig;
    use std::collections::HashMap;

    fn make_vmess_config() -> ProxyConfig {
        ProxyConfig {
            name: "vmess-test".to_string(),
            proxy_type: "vmess".to_string(),
            server: Some("1.2.3.4".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            cipher: Some("auto".to_string()),
            tls: Some(true),
            sni: Some("example.com".to_string()),
            skip_cert_verify: Some(false),
            alpn: Some(vec!["h2".to_string()]),
            client_fingerprint: Some("chrome".to_string()),
            network: Some("tcp".to_string()),
            alter_id: Some(0),
            udp: Some(true),
            tfo: Some(false),
            mptcp: Some(false),
            // Defaults for the rest
            password: None,
            udp_over_tcp: None,
            udp_over_tcp_version: None,
            plugin: None,
            plugin_opts: None,
            flow: None,
            encryption: None,
            packet_encoding: None,
            xudp: None,
            packet_addr: None,
            servername: None,
            fingerprint: None,
            certificate: None,
            private_key: None,
            reality_opts: None,
            ech_opts: None,
            ws_opts: None,
            grpc_opts: None,
            h2_opts: None,
            http_opts: None,
            ss_opts: None,
            interface_name: None,
            routing_mark: None,
            ip_version: None,
            dialer_proxy: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn vmess_outbound_from_valid_config() {
        let config = make_vmess_config();
        let outbound = VmessOutbound::new(&config).unwrap();

        assert_eq!(outbound.name, "vmess-test");
        assert_eq!(outbound.server, "1.2.3.4");
        assert_eq!(outbound.port, 443);
        assert!(outbound.tls);
        assert_eq!(outbound.sni, "example.com");
        assert_eq!(outbound.network, "tcp");
        assert!(outbound.udp);
        assert_eq!(outbound.alpn, vec!["h2".to_string()]);
        assert_eq!(outbound.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn vmess_security_auto_maps_to_aes128gcm() {
        assert_eq!(VmessSecurity::from_str("auto"), VmessSecurity::Aes128Gcm,);
    }

    #[test]
    fn vmess_security_chacha20() {
        assert_eq!(
            VmessSecurity::from_str("chacha20-poly1305"),
            VmessSecurity::Chacha20Poly1305,
        );
    }

    #[test]
    fn vmess_security_none() {
        assert_eq!(VmessSecurity::from_str("none"), VmessSecurity::None,);
    }

    #[test]
    fn vmess_security_zero_maps_to_none() {
        assert_eq!(VmessSecurity::from_str("zero"), VmessSecurity::None,);
    }

    #[test]
    fn vmess_security_aes128gcm_explicit() {
        assert_eq!(
            VmessSecurity::from_str("aes-128-gcm"),
            VmessSecurity::Aes128Gcm,
        );
    }

    #[test]
    fn vmess_security_unknown_defaults_to_aes128gcm() {
        assert_eq!(
            VmessSecurity::from_str("something-random"),
            VmessSecurity::Aes128Gcm,
        );
    }

    #[test]
    fn vmess_missing_server_fails() {
        let mut config = make_vmess_config();
        config.server = None;
        assert!(VmessOutbound::new(&config).is_err());
    }

    #[test]
    fn vmess_missing_uuid_fails() {
        let mut config = make_vmess_config();
        config.uuid = None;
        assert!(VmessOutbound::new(&config).is_err());
    }

    #[test]
    fn vmess_invalid_uuid_fails() {
        let mut config = make_vmess_config();
        config.uuid = Some("not-a-valid-uuid".to_string());
        assert!(VmessOutbound::new(&config).is_err());
    }

    #[test]
    fn vmess_sni_falls_back_to_server() {
        let mut config = make_vmess_config();
        config.sni = None;
        config.servername = None;
        let outbound = VmessOutbound::new(&config).unwrap();
        assert_eq!(outbound.sni, "1.2.3.4");
    }

    #[test]
    fn vmess_default_network_is_tcp() {
        let mut config = make_vmess_config();
        config.network = None;
        let outbound = VmessOutbound::new(&config).unwrap();
        assert_eq!(outbound.network, "tcp");
    }
}
