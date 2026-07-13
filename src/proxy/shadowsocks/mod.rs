pub mod aead;
pub mod plugin;
pub mod udp;

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::proxy::{OutboundHandler, OutboundPacketConn, ProxyStream};
use crate::transport::tcp::{connect, ConnectOpts};

use aead::{encode_address, evp_bytes_to_key, AeadCipher, SsStream};
use plugin::{ObfsStream, PluginOpts};

/// Shadowsocks outbound handler implementing the AEAD protocol.
pub struct ShadowsocksOutbound {
    name: String,
    server: String,
    port: u16,
    cipher: AeadCipher,
    master_key: Vec<u8>,
    /// For SS2022 multi-user: (server_key, user_key). None for single-user or legacy.
    identity_keys: Option<(Vec<u8>, Vec<u8>)>,
    udp: bool,
    plugin: Option<String>,
    plugin_opts: PluginOpts,
    connect_opts: ConnectOpts,
}

impl ShadowsocksOutbound {
    /// Create a new Shadowsocks outbound handler from a proxy config.
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| anyhow!("ss: missing server address"))?;
        let port = config
            .port
            .ok_or_else(|| anyhow!("ss: missing server port"))?;
        let cipher_name = config
            .cipher
            .as_deref()
            .ok_or_else(|| anyhow!("ss: missing cipher"))?;
        let password = config
            .password
            .as_deref()
            .ok_or_else(|| anyhow!("ss: missing password"))?;

        let cipher = AeadCipher::from_name(cipher_name)
            .ok_or_else(|| anyhow!("ss: unsupported cipher '{cipher_name}'"))?;

        // Derive the master key:
        // - SS2022 ciphers: password is base64-encoded raw key
        //   Multi-user format: "server_key:user_key" — decode each part, concatenate
        // - Legacy ciphers: password is derived via EVP_BytesToKey
        // For SS2022 multi-user, we need both server_key and user_key separately.
        // master_key = user_key (used for session encryption)
        // identity_keys = Some((server_key, user_key)) for identity header
        let (master_key, identity_keys) = if cipher.is_ss2022() {
            use base64::Engine;
            let decode_b64 = |s: &str| -> Result<Vec<u8>> {
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
                    .map_err(|e| anyhow!("ss2022: invalid base64 key '{s}': {e}"))
            };

            if let Some((server_b64, user_b64)) = password.split_once(':') {
                // Multi-user format: "server_key:user_key"
                let server_key = decode_b64(server_b64)?;
                let user_key = decode_b64(user_b64)?;
                if server_key.len() != cipher.key_len() || user_key.len() != cipher.key_len() {
                    return Err(anyhow!(
                        "ss2022: key length mismatch: expected {} bytes each, got server={} user={}",
                        cipher.key_len(),
                        server_key.len(),
                        user_key.len()
                    ));
                }
                // master_key = user_key (for session), identity_keys for header
                let ik = Some((server_key, user_key.clone()));
                (user_key, ik)
            } else {
                let key = decode_b64(password)?;
                if key.len() != cipher.key_len() {
                    return Err(anyhow!(
                        "ss2022: key length mismatch: expected {} bytes, got {}",
                        cipher.key_len(),
                        key.len()
                    ));
                }
                (key, None) // single user, no identity header
            }
        } else {
            let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
            (key, None)
        };

        let udp = config.udp.unwrap_or(false);
        let plugin = config.plugin.clone();
        let plugin_opts = config
            .plugin_opts
            .as_ref()
            .map(PluginOpts::from_map)
            .unwrap_or_default();

        // Unknown plugins must FAIL LOUD at config load, never silently
        // degrade to a plain TCP transport (CLAUDE.md "never silent fallback").
        match plugin.as_deref() {
            None | Some("") => {}
            Some("obfs-local") | Some("obfs") | Some("simple-obfs") | Some("v2ray-plugin") => {}
            Some("shadow-tls") | Some("shadowtls") | Some("shadow-tls-v2") => {
                // mihomo compat deviation: only shadow-tls v2 is implemented.
                // Reject a requested v3 at load instead of silently running
                // the v2 handshake against a v3 server.
                let version = config
                    .plugin_opts
                    .as_ref()
                    .and_then(|m| m.get("version"))
                    .and_then(|v| match v {
                        serde_yaml::Value::Number(n) => n.as_u64(),
                        serde_yaml::Value::String(s) => s.parse().ok(),
                        _ => None,
                    });
                if let Some(v) = version {
                    if v != 2 {
                        return Err(anyhow!(
                            "ss {server}:{port} shadow-tls version {v} not supported (only v2 is implemented)"
                        ));
                    }
                }
            }
            Some("shadow-tls-v3") => {
                return Err(anyhow!(
                    "ss {server}:{port} shadow-tls version 3 not supported (only v2 is implemented)"
                ));
            }
            Some(plugin_name) => {
                return Err(anyhow!(
                    "ss {server}:{port} plugin {plugin_name} not supported"
                ));
            }
        }

        let connect_opts = ConnectOpts::from_proxy_config(config);

        info!(
            "Shadowsocks proxy '{}': {}:{} cipher={} udp={}",
            config.name, server, port, cipher_name, udp
        );

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            cipher,
            master_key,
            identity_keys,
            udp,
            plugin,
            plugin_opts,
            connect_opts,
        })
    }

    /// Establish a raw TCP connection to the SS server, resolving the server
    /// address via DNS if needed.
    async fn connect_to_server(&self, dns: &DnsResolver) -> Result<TcpStream> {
        let addr = {
            let ip = dns
                .resolve_proxy_server(&self.server)
                .await
                .map_err(|e| anyhow!("ss: failed to resolve server '{}': {}", self.server, e))?;
            std::net::SocketAddr::new(ip, self.port)
        };

        debug!(
            "ss: connecting to server {} ({}:{})",
            self.server,
            addr.ip(),
            addr.port()
        );
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connect(addr, &self.connect_opts),
        )
        .await
        .map_err(|_| anyhow!("ss: TCP connect timeout to {}:{}", addr.ip(), addr.port()))?
        .map_err(|e| {
            anyhow!(
                "ss: TCP connect failed to {}:{}: {}",
                addr.ip(),
                addr.port(),
                e
            )
        })?;
        debug!("ss: TCP connected to {}:{}", addr.ip(), addr.port());
        Ok(stream)
    }

    /// Wrap a transport in the AEAD encrypted stream and flush the handshake.
    async fn wrap_aead<S>(&self, transport: S, addr_header: Vec<u8>) -> Result<Box<dyn ProxyStream>>
    where
        S: ProxyStream + 'static,
    {
        let mut ss = SsStream::new(
            transport,
            self.cipher,
            self.master_key.clone(),
            addr_header,
            self.identity_keys.clone(),
        );
        // mihomo compat: flush handshake to wire immediately (like DialConn)
        ss.flush_handshake()
            .await
            .map_err(|e| anyhow!("ss handshake flush: {e}"))?;
        Ok(Box::new(ss))
    }
}

#[async_trait]
impl OutboundHandler for ShadowsocksOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "Shadowsocks"
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
            "ss: connect_stream to {} via {}:{}",
            target, self.server, self.port
        );

        // Connect TCP to the SS server
        let tcp_stream = self.connect_to_server(dns).await?;

        // Encode the target address as the initial payload (first chunk).
        // The SS server will parse this header and connect to the target on our behalf.
        let addr_header = encode_address(target);

        // Decide transport based on plugin field.
        match self.plugin.as_deref() {
            None | Some("") => {
                // Direct TCP - wrap in AEAD encrypted stream
                self.wrap_aead(tcp_stream, addr_header).await
            }

            Some("obfs-local") | Some("obfs") | Some("simple-obfs") => {
                // simple-obfs: wrap TCP in HTTP or TLS obfuscation, then AEAD
                let mode = self.plugin_opts.mode.as_deref().unwrap_or("http");
                let host = self.plugin_opts.host.as_deref().unwrap_or(&self.server);

                debug!("ss: using simple-obfs mode={} host={}", mode, host);

                let obfs_stream = match mode {
                    "tls" => ObfsStream::new_tls(tcp_stream, host.to_string()),
                    _ => ObfsStream::new_http(tcp_stream, host.to_string()),
                };

                self.wrap_aead(obfs_stream, addr_header).await
            }

            Some("v2ray-plugin") => {
                // v2ray-plugin: wrap TCP in (optional TLS +) WebSocket, then AEAD
                debug!("ss: using v2ray-plugin");

                let transport =
                    plugin::connect_v2ray_plugin(tcp_stream, &self.plugin_opts, &self.server)
                        .await
                        .map_err(|e| anyhow!("ss: v2ray-plugin setup failed: {e}"))?;

                self.wrap_aead(transport, addr_header).await
            }

            Some("shadow-tls") | Some("shadowtls") | Some("shadow-tls-v2") => {
                // shadow-tls: TLS handshake + HMAC-authenticated data, then AEAD
                debug!("ss: using shadow-tls");

                let stls_stream =
                    plugin::connect_shadow_tls(tcp_stream, &self.plugin_opts, &self.server)
                        .await
                        .map_err(|e| anyhow!("ss: shadow-tls setup failed: {e}"))?;

                self.wrap_aead(stls_stream, addr_header).await
            }

            // Unknown plugins are rejected in from_config; unreachable in practice.
            Some(plugin_name) => Err(anyhow!("ss: plugin '{plugin_name}' not supported")),
        }
    }

    async fn connect_datagram(
        &self,
        _target: &Address,
        dns: Arc<DnsResolver>,
    ) -> Result<Box<dyn OutboundPacketConn>> {
        if !self.udp {
            return Err(anyhow!("ss: UDP not enabled for proxy '{}'", self.name));
        }

        // Resolve server address
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let server_addr = std::net::SocketAddr::new(ip, self.port);

        debug!(
            "ss: creating UDP socket to {}:{} for proxy '{}'",
            self.server, self.port, self.name
        );

        let socket =
            udp::SsUdpSocket::new(server_addr, self.cipher, self.master_key.clone()).await?;
        Ok(Box::new(socket))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::ProxyConfig;
    use std::collections::HashMap;

    fn make_ss_config() -> ProxyConfig {
        ProxyConfig {
            name: "ss-test".to_string(),
            proxy_type: "ss".to_string(),
            server: Some("1.2.3.4".to_string()),
            port: Some(8388),
            cipher: Some("aes-256-gcm".to_string()),
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
            xhttp_opts: None,
            ss_opts: None,
            udp_over_tcp: None,
            udp_over_tcp_version: None,
            plugin: None,
            plugin_opts: None,
            interface_name: None,
            routing_mark: None,
            tcp_concurrent: None,
            ip_version: None,
            dialer_proxy: None,
            keep_alive_idle: None,
            keep_alive_interval: None,
            disable_keep_alive: None,
            extra: HashMap::new(),
        }
    }

    /// Unknown plugins must FAIL LOUD at config load, never silently fall
    /// back to a plain TCP transport.
    #[test]
    fn ss_unknown_plugin_rejected_at_load() {
        for plugin in ["restls", "kcptun", "does-not-exist"] {
            let mut config = make_ss_config();
            config.plugin = Some(plugin.to_string());
            let err = match ShadowsocksOutbound::from_config(&config) {
                Ok(_) => panic!("plugin {plugin} must be rejected"),
                Err(e) => e.to_string(),
            };
            assert!(
                err.contains(&format!("plugin {plugin} not supported")),
                "unexpected error for {plugin}: {err}"
            );
        }
    }

    /// shadow-tls v3 is not implemented; requesting it must be a load-time
    /// error rather than silently running the v2 handshake.
    #[test]
    fn ss_shadow_tls_v3_rejected_at_load() {
        // Via the plugin name alias.
        let mut config = make_ss_config();
        config.plugin = Some("shadow-tls-v3".to_string());
        assert!(ShadowsocksOutbound::from_config(&config).is_err());

        // Via plugin-opts version.
        let mut config = make_ss_config();
        config.plugin = Some("shadow-tls".to_string());
        let mut opts = HashMap::new();
        opts.insert(
            "version".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(3)),
        );
        config.plugin_opts = Some(opts);
        assert!(ShadowsocksOutbound::from_config(&config).is_err());
    }

    #[test]
    fn ss_known_plugins_accepted_at_load() {
        for plugin in ["", "obfs", "obfs-local", "v2ray-plugin", "shadow-tls"] {
            let mut config = make_ss_config();
            config.plugin = if plugin.is_empty() {
                None
            } else {
                Some(plugin.to_string())
            };
            assert!(
                ShadowsocksOutbound::from_config(&config).is_ok(),
                "plugin '{plugin}' should be accepted"
            );
        }
    }
}
