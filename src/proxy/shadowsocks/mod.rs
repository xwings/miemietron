pub mod aead;
pub mod plugin;
pub mod udp;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::proxy::{OutboundHandler, ProxyStream};
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
            .ok_or_else(|| anyhow!("ss: unsupported cipher '{}'", cipher_name))?;

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
                    .map_err(|e| anyhow!("ss2022: invalid base64 key '{}': {}", s, e))
            };

            if password.contains(':') {
                // Multi-user format: "server_key:user_key"
                let parts: Vec<&str> = password.splitn(2, ':').collect();
                let server_key = decode_b64(parts[0])?;
                let user_key = decode_b64(parts[1])?;
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

        let connect_opts = ConnectOpts {
            interface: config.interface_name.clone(),
            routing_mark: config.routing_mark,
            tfo: config.tfo.unwrap_or(false),
            mptcp: config.mptcp.unwrap_or(false),
        };

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

        info!("ss: connecting to server {} ({}:{})", self.server, addr.ip(), addr.port());
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connect(addr, &self.connect_opts),
        )
        .await
        .map_err(|_| anyhow!("ss: TCP connect timeout to {}:{}", addr.ip(), addr.port()))?
        .map_err(|e| anyhow!("ss: TCP connect failed to {}:{}: {}", addr.ip(), addr.port(), e))?;
        info!("ss: TCP connected to {}:{}", addr.ip(), addr.port());
        Ok(stream)
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
                let ss = SsStream::new(
                    tcp_stream,
                    self.cipher,
                    self.master_key.clone(),
                    addr_header,
                    self.identity_keys.clone(),
                );
                Ok(Box::new(ss))
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

                let ss = SsStream::new(
                    obfs_stream,
                    self.cipher,
                    self.master_key.clone(),
                    addr_header,
                    self.identity_keys.clone(),
                );
                Ok(Box::new(ss))
            }

            Some("v2ray-plugin") => {
                // v2ray-plugin: wrap TCP in (optional TLS +) WebSocket, then AEAD
                debug!("ss: using v2ray-plugin");

                let transport =
                    plugin::connect_v2ray_plugin(tcp_stream, &self.plugin_opts, &self.server)
                        .await
                        .map_err(|e| anyhow!("ss: v2ray-plugin setup failed: {}", e))?;

                let ss = SsStream::new(
                    transport,
                    self.cipher,
                    self.master_key.clone(),
                    addr_header,
                    self.identity_keys.clone(),
                );
                Ok(Box::new(ss))
            }

            Some("shadow-tls") | Some("shadowtls") | Some("shadow-tls-v2") => {
                // shadow-tls: TLS handshake + HMAC-authenticated data, then AEAD
                debug!("ss: using shadow-tls");

                let stls_stream =
                    plugin::connect_shadow_tls(tcp_stream, &self.plugin_opts, &self.server)
                        .await
                        .map_err(|e| anyhow!("ss: shadow-tls setup failed: {}", e))?;

                let ss = SsStream::new(
                    stls_stream,
                    self.cipher,
                    self.master_key.clone(),
                    addr_header,
                    self.identity_keys.clone(),
                );
                Ok(Box::new(ss))
            }

            Some(plugin_name) => {
                // Unknown plugin -- fall back to direct TCP with a warning.
                tracing::warn!(
                    "ss: plugin '{}' not supported, using direct TCP",
                    plugin_name
                );
                let ss = SsStream::new(
                    tcp_stream,
                    self.cipher,
                    self.master_key.clone(),
                    addr_header,
                    self.identity_keys.clone(),
                );
                Ok(Box::new(ss))
            }
        }
    }
}
