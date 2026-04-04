//! ShadowsocksR (SSR) protocol adapter.
//!
//! SSR extends Shadowsocks with:
//! - Stream ciphers (AES-CFB, ChaCha20, RC4-MD5) instead of AEAD.
//! - Protocol plugins (auth_aes128, auth_chain, origin) for anti-detection.
//! - Obfuscation plugins (plain, http_simple, tls1.2_ticket_auth) to disguise traffic.
//!
//! Data flow:
//!   TCP connect -> obfs plugin -> stream cipher (IV + encrypt) -> protocol plugin -> relay
//!
//! The SSR address header is the same format as Shadowsocks:
//!   [addr_type(1)][addr_data][port(2 big-endian)]

pub mod obfs;
pub mod protocol;
pub mod stream;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::proxy::shadowsocks::aead::encode_address;
use crate::proxy::{OutboundHandler, ProxyStream};
use crate::transport::tcp::{connect, ConnectOpts};

use obfs::{SsrObfs, SsrObfsStream};
use protocol::{SsrProtocol, SsrProtocolStream};
use stream::{SsrCipher, SsrStream};

/// ShadowsocksR outbound handler.
pub struct SsrOutbound {
    name: String,
    server: String,
    port: u16,
    cipher: SsrCipher,
    password: String,
    obfs: SsrObfs,
    obfs_param: String,
    protocol: SsrProtocol,
    protocol_param: String,
    udp: bool,
    connect_opts: ConnectOpts,
}

impl SsrOutbound {
    /// Create a new SSR outbound handler from a proxy config.
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| anyhow!("ssr: missing server address"))?;
        let port = config
            .port
            .ok_or_else(|| anyhow!("ssr: missing server port"))?;
        let cipher_name = config
            .cipher
            .as_deref()
            .ok_or_else(|| anyhow!("ssr: missing cipher"))?;
        let password = config
            .password
            .clone()
            .ok_or_else(|| anyhow!("ssr: missing password"))?;

        let cipher = SsrCipher::from_name(cipher_name)
            .ok_or_else(|| anyhow!("ssr: unsupported cipher '{}'", cipher_name))?;

        // SSR-specific fields: obfs, obfs-param, protocol, protocol-param.
        // These come from the `extra` catch-all map in ProxyConfig since they
        // are not standard SS fields.
        let obfs_name = config
            .extra
            .get("obfs")
            .and_then(|v| v.as_str())
            .unwrap_or("plain");
        let obfs = SsrObfs::from_name(obfs_name)
            .ok_or_else(|| anyhow!("ssr: unsupported obfs plugin '{}'", obfs_name))?;

        let obfs_param = config
            .extra
            .get("obfs-param")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let protocol_name = config
            .extra
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("origin");
        let protocol = SsrProtocol::from_name(protocol_name)
            .ok_or_else(|| anyhow!("ssr: unsupported protocol plugin '{}'", protocol_name))?;

        let protocol_param = config
            .extra
            .get("protocol-param")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let udp = config.udp.unwrap_or(false);

        let connect_opts = ConnectOpts {
            interface: config.interface_name.clone(),
            routing_mark: config.routing_mark,
            tfo: config.tfo.unwrap_or(false),
            mptcp: config.mptcp.unwrap_or(false),
        };

        info!(
            "SSR proxy '{}': {}:{} cipher={} obfs={} protocol={} udp={}",
            config.name, server, port, cipher_name, obfs_name, protocol_name, udp
        );

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            cipher,
            password,
            obfs,
            obfs_param,
            protocol,
            protocol_param,
            udp,
            connect_opts,
        })
    }

    /// Establish a raw TCP connection to the SSR server.
    async fn connect_to_server(&self, dns: &DnsResolver) -> Result<TcpStream> {
        let addr = {
            let ip = dns
                .resolve_proxy_server(&self.server)
                .await
                .map_err(|e| anyhow!("ssr: failed to resolve server '{}': {}", self.server, e))?;
            std::net::SocketAddr::new(ip, self.port)
        };

        debug!("ssr: connecting to server {}:{}", addr.ip(), addr.port());
        let stream = connect(addr, &self.connect_opts).await?;
        Ok(stream)
    }
}

#[async_trait]
impl OutboundHandler for SsrOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "ShadowsocksR"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        debug!(
            "ssr: connect_stream to {} via {}:{}",
            target, self.server, self.port
        );

        // 1. TCP connect to the SSR server.
        let tcp_stream = self.connect_to_server(dns).await?;

        // 2. Wrap in stream cipher (handles IV send/receive + encryption).
        let cipher_stream = SsrStream::new(tcp_stream, self.cipher, &self.password);

        // 3. Wrap in protocol plugin (origin = passthrough, others = stub).
        let protocol_stream =
            SsrProtocolStream::new(cipher_stream, self.protocol, &self.protocol_param);

        // 4. Wrap in obfuscation plugin.
        let obfs_stream = SsrObfsStream::new(protocol_stream, self.obfs, self.obfs_param.clone());

        // 5. Send the target address header through the wrapped stream.
        //    The SS/SSR server expects the first payload to be the address header.
        let addr_header = encode_address(target);
        use tokio::io::AsyncWriteExt;
        let mut stream = obfs_stream;
        stream
            .write_all(&addr_header)
            .await
            .map_err(|e| anyhow!("ssr: failed to send address header: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| anyhow!("ssr: failed to flush address header: {}", e))?;

        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::ProxyConfig;
    use std::collections::HashMap;

    fn make_ssr_config() -> ProxyConfig {
        let mut extra = HashMap::new();
        extra.insert(
            "obfs".to_string(),
            serde_yaml::Value::String("http_simple".to_string()),
        );
        extra.insert(
            "obfs-param".to_string(),
            serde_yaml::Value::String("cdn.example.com".to_string()),
        );
        extra.insert(
            "protocol".to_string(),
            serde_yaml::Value::String("auth_aes128_md5".to_string()),
        );
        extra.insert(
            "protocol-param".to_string(),
            serde_yaml::Value::String("12345:abcdef".to_string()),
        );

        ProxyConfig {
            name: "ssr-test".to_string(),
            proxy_type: "ssr".to_string(),
            server: Some("1.2.3.4".to_string()),
            port: Some(8388),
            cipher: Some("aes-256-cfb".to_string()),
            password: Some("test-password".to_string()),
            udp: Some(true),
            tfo: Some(false),
            mptcp: Some(false),
            // Defaults for the rest
            uuid: None,
            alter_id: None,
            flow: None,
            encryption: None,
            packet_encoding: None,
            xudp: None,
            packet_addr: None,
            tls: None,
            sni: None,
            servername: None,
            skip_cert_verify: None,
            fingerprint: None,
            client_fingerprint: None,
            alpn: None,
            certificate: None,
            private_key: None,
            reality_opts: None,
            ech_opts: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            h2_opts: None,
            http_opts: None,
            ss_opts: None,
            udp_over_tcp: None,
            udp_over_tcp_version: None,
            plugin: None,
            plugin_opts: None,
            interface_name: None,
            routing_mark: None,
            ip_version: None,
            dialer_proxy: None,
            extra,
        }
    }

    #[test]
    fn ssr_outbound_from_valid_config() {
        let config = make_ssr_config();
        let outbound = SsrOutbound::from_config(&config).unwrap();

        assert_eq!(outbound.name, "ssr-test");
        assert_eq!(outbound.server, "1.2.3.4");
        assert_eq!(outbound.port, 8388);
        assert_eq!(outbound.cipher, SsrCipher::Aes256Cfb);
        assert_eq!(outbound.password, "test-password");
        assert_eq!(outbound.obfs, SsrObfs::HttpSimple);
        assert_eq!(outbound.obfs_param, "cdn.example.com");
        assert_eq!(outbound.protocol, SsrProtocol::AuthAes128Md5);
        assert_eq!(outbound.protocol_param, "12345:abcdef");
        assert!(outbound.udp);
    }

    #[test]
    fn ssr_cipher_name_mapping() {
        assert_eq!(
            SsrCipher::from_name("aes-256-cfb"),
            Some(SsrCipher::Aes256Cfb)
        );
        assert_eq!(
            SsrCipher::from_name("aes-128-cfb"),
            Some(SsrCipher::Aes128Cfb)
        );
        assert_eq!(
            SsrCipher::from_name("chacha20-ietf"),
            Some(SsrCipher::ChaCha20Ietf)
        );
        assert_eq!(SsrCipher::from_name("rc4-md5"), Some(SsrCipher::Rc4Md5));
        assert_eq!(SsrCipher::from_name("none"), Some(SsrCipher::None));
        assert_eq!(SsrCipher::from_name("plain"), Some(SsrCipher::None));
        assert_eq!(SsrCipher::from_name("table"), Some(SsrCipher::None));
        assert_eq!(SsrCipher::from_name("unsupported"), None);
    }

    #[test]
    fn ssr_obfs_from_name() {
        assert_eq!(SsrObfs::from_name("plain"), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_name(""), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_name("http_simple"), Some(SsrObfs::HttpSimple));
        assert_eq!(SsrObfs::from_name("http-simple"), Some(SsrObfs::HttpSimple));
        assert_eq!(
            SsrObfs::from_name("tls1.2_ticket_auth"),
            Some(SsrObfs::Tls12TicketAuth)
        );
        assert_eq!(SsrObfs::from_name("unknown"), None);
    }

    #[test]
    fn ssr_protocol_from_name() {
        assert_eq!(SsrProtocol::from_name("origin"), Some(SsrProtocol::Origin));
        assert_eq!(SsrProtocol::from_name(""), Some(SsrProtocol::Origin));
        assert_eq!(
            SsrProtocol::from_name("auth_aes128_md5"),
            Some(SsrProtocol::AuthAes128Md5)
        );
        assert_eq!(
            SsrProtocol::from_name("auth_aes128_sha1"),
            Some(SsrProtocol::AuthAes128Sha1)
        );
        assert_eq!(
            SsrProtocol::from_name("auth_chain_a"),
            Some(SsrProtocol::AuthChainA)
        );
        assert_eq!(
            SsrProtocol::from_name("auth_chain_b"),
            Some(SsrProtocol::AuthChainB)
        );
        assert_eq!(SsrProtocol::from_name("unknown"), None);
    }

    #[test]
    fn ssr_defaults_obfs_protocol_when_missing() {
        let mut config = make_ssr_config();
        config.extra.clear(); // no obfs/protocol specified

        let outbound = SsrOutbound::from_config(&config).unwrap();
        assert_eq!(outbound.obfs, SsrObfs::Plain);
        assert_eq!(outbound.protocol, SsrProtocol::Origin);
        assert_eq!(outbound.obfs_param, "");
        assert_eq!(outbound.protocol_param, "");
    }

    #[test]
    fn ssr_missing_server_fails() {
        let mut config = make_ssr_config();
        config.server = None;
        assert!(SsrOutbound::from_config(&config).is_err());
    }

    #[test]
    fn ssr_missing_cipher_fails() {
        let mut config = make_ssr_config();
        config.cipher = None;
        assert!(SsrOutbound::from_config(&config).is_err());
    }

    #[test]
    fn ssr_unsupported_cipher_fails() {
        let mut config = make_ssr_config();
        config.cipher = Some("blowfish-cfb".to_string());
        assert!(SsrOutbound::from_config(&config).is_err());
    }
}
