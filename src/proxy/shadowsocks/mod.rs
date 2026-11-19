pub mod aead;
pub mod plugin;
pub mod stream;
#[cfg(test)]
mod test_support;
pub mod udp;

use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::proxy::uot::{self, UotPacketConn};
use crate::proxy::{Handshake, OutboundHandler, OutboundPacketConn, ProxyStream};
use crate::transport::tcp::{connect, ConnectOpts};

use aead::{encode_address, evp_bytes_to_key, AeadCipher, SsStream};
use plugin::{ObfsStream, PluginOpts};
use stream::{CipherStream, StreamCipher};
use udp::{PacketCodec, Session2022};

/// Methods sing-shadowsocks2 registers that are not implemented here.
const UNIMPLEMENTED_METHODS: &[&str] = &[
    "chacha8-ietf-poly1305",
    "xchacha8-ietf-poly1305",
    "rabbit128-poly1305",
    "aes-128-ccm",
    "aes-192-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
    "aegis-128l",
    "aegis-256",
    "aez-384",
    "deoxys-ii-256-128",
    "lea-128-gcm",
    "lea-192-gcm",
    "lea-256-gcm",
    "ascon128",
    "ascon128a",
    "2022-blake3-chacha8-poly1305",
    "2022-blake3-aes-128-ccm",
    "2022-blake3-aes-256-ccm",
];

/// Host the simple-obfs and v2ray-plugin options default to.
const DEFAULT_PLUGIN_HOST: &str = "bing.com";

/// A cipher with its key material — what sing-shadowsocks2's
/// `shadowsocks.CreateMethod` makes of `cipher` and `password`.
enum Method {
    /// `shadowstream/method.go`, and `none` (`cipher/method_none.go`).
    Stream { cipher: StreamCipher, key: Vec<u8> },
    /// `shadowaead/method.go`: the key is derived from the password.
    Aead { cipher: AeadCipher, key: Vec<u8> },
    /// `shadowaead_2022/method.go`: the password is a `:`-separated list of
    /// base64 PSKs, identity PSKs first and the user's own last.
    Aead2022 {
        cipher: AeadCipher,
        identity_psks: Vec<Vec<u8>>,
        psk: Vec<u8>,
    },
}

impl Method {
    /// mihomo compat: the errors are sing-shadowsocks2's, which
    /// `NewShadowSocks` reports as `ss <addr> cipher: <cipher> initialize
    /// error: <err>`.
    fn new(name: &str, password: &str) -> Result<Self> {
        if let Some(cipher) = StreamCipher::from_name(name) {
            // `none` has no key: its password is not looked at.
            if cipher != StreamCipher::None && password.is_empty() {
                bail!("missing password");
            }
            let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
            return Ok(Method::Stream { cipher, key });
        }

        let Some(cipher) = AeadCipher::from_name(name) else {
            if UNIMPLEMENTED_METHODS.contains(&name.to_lowercase().as_str()) {
                bail!("method not implemented");
            }
            bail!("unknown method: {name}");
        };

        if !cipher.is_ss2022() {
            if password.is_empty() {
                bail!("missing password");
            }
            let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
            return Ok(Method::Aead { cipher, key });
        }

        let mut psks = Vec::new();
        if !password.is_empty() {
            for encoded in password.split(':') {
                psks.push(decode_psk(encoded).map_err(|e| anyhow!("decode key: {e}"))?);
            }
        }
        if cipher == AeadCipher::Blake3ChaCha20Poly1305 && psks.len() > 1 {
            bail!("Shadowsocks 2022 EIH support only available in AES ciphers");
        }
        if let Some(key) = psks.iter().find(|key| key.len() != cipher.key_len()) {
            bail!(
                "bad key length, required {}, got {}",
                cipher.key_len(),
                key.len()
            );
        }
        let Some(psk) = psks.pop() else {
            bail!("missing password");
        };
        Ok(Method::Aead2022 {
            cipher,
            identity_psks: psks,
            psk,
        })
    }
}

/// Decode one SS2022 PSK as Go's `base64.StdEncoding.DecodeString` does: the
/// standard alphabet with its padding, line breaks skipped and — the encoding
/// not being `Strict()` — stray trailing bits let through.
fn decode_psk(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::Engine;

    const GO_STD_ENCODING: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    GO_STD_ENCODING.decode(encoded.replace(['\r', '\n'], ""))
}

/// The transport a plugin puts between the TCP connection and the cipher.
enum Plugin {
    None,
    /// simple-obfs in http mode.
    ObfsHttp {
        host: String,
    },
    /// v2ray-plugin: WebSocket, over TLS when asked.
    V2ray {
        host: String,
        path: String,
        tls: bool,
    },
}

impl Plugin {
    /// mihomo compat: the plugin branches of `NewShadowSocks`
    /// (adapter/outbound/shadowsocks.go) — their defaults, their mode checks
    /// and error texts. A plugin or plugin mode whose wire protocol is not
    /// implemented here fails the load rather than yield a connection that
    /// can never work.
    fn from_config(config: &ProxyConfig, addr: &str) -> Result<Self> {
        let opts = config
            .plugin_opts
            .as_ref()
            .map(PluginOpts::from_map)
            .unwrap_or_default();
        let host = || {
            opts.host
                .clone()
                .unwrap_or_else(|| DEFAULT_PLUGIN_HOST.to_string())
        };
        let mode = opts.mode.as_deref().unwrap_or_default();

        match config.plugin.as_deref().unwrap_or_default() {
            "obfs" => match mode {
                "http" => Ok(Plugin::ObfsHttp { host: host() }),
                "tls" => bail!("ss {addr} obfs mode tls is not implemented"),
                _ => bail!("ss {addr} obfs mode error: {mode}"),
            },
            "v2ray-plugin" => {
                if mode != "websocket" {
                    bail!("ss {addr} obfs mode error: {mode}");
                }
                // mihomo compat: mux is on unless the options turn it off.
                if opts.mux.unwrap_or(true) {
                    bail!("ss {addr} v2ray-plugin mux is not implemented, set mux: false");
                }
                if opts.v2ray_http_upgrade {
                    bail!("ss {addr} v2ray-plugin v2ray-http-upgrade is not implemented");
                }
                Ok(Plugin::V2ray {
                    host: host(),
                    path: opts.path.clone().unwrap_or_else(|| "/".to_string()),
                    tls: opts.tls,
                })
            }
            plugin @ ("gost-plugin" | "shadow-tls" | "restls" | "jls" | "kcptun") => {
                bail!("ss {addr} plugin {plugin} is not implemented")
            }
            // mihomo compat: any other name is no plugin at all — the
            // if/else-if chain over `option.Plugin` has no final else.
            _ => Ok(Plugin::None),
        }
    }
}

/// Go's `net.JoinHostPort`: the server address as mihomo's errors print it.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Shadowsocks outbound handler.
pub struct ShadowsocksOutbound {
    name: String,
    server: String,
    port: u16,
    method: Method,
    udp: bool,
    udp_over_tcp: bool,
    /// `uot::VERSION` or `uot::LEGACY_VERSION`.
    udp_over_tcp_version: u8,
    plugin: Plugin,
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

        let addr = join_host_port(&server, port);
        let method = Method::new(cipher_name, password)
            .map_err(|e| anyhow!("ss {addr} cipher: {cipher_name} initialize error: {e}"))?;

        let udp = config.udp.unwrap_or(false);
        let plugin = Plugin::from_config(config, &addr)?;

        // mihomo compat: NewShadowSocks checks the version whether or not
        // `udp-over-tcp` is on; left unset it is the legacy protocol.
        let udp_over_tcp_version = match config.udp_over_tcp_version.unwrap_or(0) {
            0 | uot::LEGACY_VERSION => uot::LEGACY_VERSION,
            uot::VERSION => uot::VERSION,
            version => bail!("ss {addr} unknown udp over tcp protocol version: {version}"),
        };

        let connect_opts = ConnectOpts::from_proxy_config(config);

        info!(
            "Shadowsocks proxy '{}': {}:{} cipher={} udp={}",
            config.name, server, port, cipher_name, udp
        );

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            method,
            udp,
            udp_over_tcp: config.udp_over_tcp.unwrap_or(false),
            udp_over_tcp_version,
            plugin,
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

    /// Wrap a transport in the method's stream. The request header — the
    /// address header, under the cipher — stays pending until the stream's
    /// first write (see [`OutboundHandler::handshake`]).
    fn wrap_method<S>(&self, transport: S, addr_header: Vec<u8>) -> Result<Box<dyn ProxyStream>>
    where
        S: ProxyStream + 'static,
    {
        Ok(match &self.method {
            Method::Stream { cipher, key } => Box::new(CipherStream::new(
                transport,
                *cipher,
                key.clone(),
                addr_header,
            )?),
            Method::Aead { cipher, key } => Box::new(SsStream::new(
                transport,
                *cipher,
                key.clone(),
                addr_header,
                &[],
            )),
            Method::Aead2022 {
                cipher,
                identity_psks,
                psk,
            } => Box::new(SsStream::new(
                transport,
                *cipher,
                psk.clone(),
                addr_header,
                identity_psks,
            )),
        })
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

    fn handshake(&self) -> Handshake {
        // mihomo compat: shadowsocks.go StreamConnContext. `useEarly` is only
        // raised by plugins that do not load here (shadow-tls, restls, jls),
        // so `method.DialConn` writes the request while dialing, ahead of
        // any payload.
        Handshake::AtDial
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
        match &self.plugin {
            // Direct TCP - wrap in the method's encrypted stream
            Plugin::None => self.wrap_method(tcp_stream, addr_header),

            Plugin::ObfsHttp { host } => {
                // simple-obfs: wrap TCP in HTTP obfuscation, then the method
                debug!("ss: using simple-obfs mode=http host={}", host);
                self.wrap_method(ObfsStream::new_http(tcp_stream, host.clone()), addr_header)
            }

            Plugin::V2ray { host, path, tls } => {
                // v2ray-plugin: wrap TCP in (optional TLS +) WebSocket, then the method
                debug!("ss: using v2ray-plugin");

                let transport = plugin::connect_v2ray_plugin(tcp_stream, host, path, *tls)
                    .await
                    .map_err(|e| anyhow!("ss: v2ray-plugin setup failed: {e}"))?;

                self.wrap_method(transport, addr_header)
            }
        }
    }

    async fn connect_datagram(
        &self,
        target: &Address,
        dns: Arc<DnsResolver>,
    ) -> Result<Box<dyn OutboundPacketConn>> {
        if !self.udp {
            return Err(anyhow!("ss: UDP not enabled for proxy '{}'", self.name));
        }

        if self.udp_over_tcp {
            // mihomo compat: ListenPacketContext with `udp-over-tcp` — the
            // packets travel on a stream opened to the UoT magic address,
            // whose request header `DialContext` sends while dialing.
            debug!(
                "ss: UDP over TCP v{} for proxy '{}'",
                self.udp_over_tcp_version, self.name
            );
            let magic = uot::request_destination(self.udp_over_tcp_version);
            let mut stream = self.connect_stream(&magic, &dns).await?;
            // An empty write sends the pending request, as the tunnel's does
            // for TCP (`Handshake::AtDial`).
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, &[])).await?;
            stream.flush().await?;

            let request = uot::Request {
                is_connect: false,
                destination: target.clone(),
            };
            return Ok(if self.udp_over_tcp_version == uot::LEGACY_VERSION {
                Box::new(UotPacketConn::new(stream, request))
            } else {
                Box::new(UotPacketConn::new_lazy(stream, request))
            });
        }

        // Resolve server address
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let server_addr = std::net::SocketAddr::new(ip, self.port);

        debug!(
            "ss: creating UDP socket to {}:{} for proxy '{}'",
            self.server, self.port, self.name
        );

        let codec = match &self.method {
            Method::Stream { cipher, key } => PacketCodec::Stream {
                cipher: *cipher,
                key: key.clone(),
            },
            Method::Aead { cipher, key } => PacketCodec::Aead {
                cipher: *cipher,
                key: key.clone(),
            },
            Method::Aead2022 {
                cipher,
                identity_psks,
                psk,
            } => PacketCodec::Aead2022(Box::new(Session2022::new(*cipher, identity_psks, psk))),
        };
        let socket = udp::SsUdpSocket::new(server_addr, codec, &self.connect_opts).await?;
        Ok(Box::new(socket))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        blake3_subkey, read_request_2022, response_2022, StreamKey, UdpServer2022, SESSION_SUBKEY,
    };
    use super::*;
    use crate::config::proxy::ProxyConfig;
    use base64::Engine;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, UdpSocket};

    fn ss_config(options: &str) -> ProxyConfig {
        serde_yaml::from_str(&format!(
            "{{name: ss-test, type: ss, server: 1.2.3.4, port: 8388, {options}}}"
        ))
        .unwrap()
    }

    fn make_ss_config() -> ProxyConfig {
        ss_config("cipher: aes-256-gcm, password: test-password, udp: true")
    }

    fn load(options: &str) -> Result<ShadowsocksOutbound> {
        ShadowsocksOutbound::from_config(&ss_config(options))
    }

    fn load_error(options: &str) -> String {
        match load(options) {
            Ok(_) => panic!("{options} must not load"),
            Err(e) => e.to_string(),
        }
    }

    fn base64_key(key: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    async fn dns() -> Arc<DnsResolver> {
        Arc::new(
            DnsResolver::new(&crate::config::DnsConfig::default())
                .await
                .unwrap(),
        )
    }

    /// mihomo compat: the names are those of sing-shadowsocks2's method
    /// registry (`cipher/method_registry.go` CreateMethod), which is all the
    /// outbound knows — `plain` or `dummy` are not among them.
    #[test]
    fn ss_methods_load_or_fail_by_name() {
        for cipher in [
            "none",
            "aes-128-gcm",
            "aes-192-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "rc4-md5",
            "chacha20-ietf",
            "xchacha20",
            "chacha20",
        ] {
            assert!(
                load(&format!("cipher: {cipher}, password: secret")).is_ok(),
                "{cipher}"
            );
        }
        for (cipher, key_len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
            ("2022-blake3-chacha20-poly1305", 32),
        ] {
            let key = base64_key(&vec![7u8; key_len]);
            assert!(
                load(&format!("cipher: {cipher}, password: '{key}'")).is_ok(),
                "{cipher}"
            );
        }

        // Registered upstream but not implemented here: said so, at load.
        for cipher in UNIMPLEMENTED_METHODS {
            assert_eq!(
                load_error(&format!("cipher: {cipher}, password: secret")),
                format!(
                    "ss 1.2.3.4:8388 cipher: {cipher} initialize error: method not implemented"
                )
            );
        }
        for cipher in ["plain", "dummy", "aes-128-cfb8", "salsa20"] {
            assert_eq!(
                load_error(&format!("cipher: {cipher}, password: secret")),
                format!(
                    "ss 1.2.3.4:8388 cipher: {cipher} initialize error: unknown method: {cipher}"
                )
            );
        }
    }

    /// mihomo compat: every method but `none` wants a password
    /// (`C.ErrMissingPassword`).
    #[test]
    fn ss_password_is_required_except_by_none() {
        for cipher in ["aes-256-gcm", "aes-256-cfb", "2022-blake3-aes-128-gcm"] {
            assert_eq!(
                load_error(&format!("cipher: {cipher}, password: ''")),
                format!("ss 1.2.3.4:8388 cipher: {cipher} initialize error: missing password")
            );
        }
        assert!(load("cipher: none, password: ''").is_ok());
    }

    /// mihomo compat: `shadowaead_2022/method.go` NewMethod — the password is
    /// split on every `:`, each part is standard padded base64, every key has
    /// the method's length, and only the AES methods take more than one.
    #[test]
    fn ss2022_key_list_follows_sing_shadowsocks2() {
        let keys: Vec<Vec<u8>> = (1..=3u8).map(|i| vec![i; 16]).collect();
        let encoded: Vec<String> = keys.iter().map(|key| base64_key(key)).collect();

        for count in 1..=3 {
            let password = encoded[..count].join(":");
            let outbound = load(&format!(
                "cipher: 2022-blake3-aes-128-gcm, password: '{password}'"
            ))
            .unwrap();
            let Method::Aead2022 {
                identity_psks, psk, ..
            } = outbound.method
            else {
                panic!("an SS2022 method");
            };
            assert_eq!(identity_psks, keys[..count - 1]);
            assert_eq!(psk, keys[count - 1]);
        }

        // A line break around a key is skipped, as Go's decoder does.
        assert!(load(&format!(
            "cipher: 2022-blake3-aes-128-gcm, password: \"{}\\n\"",
            encoded[0]
        ))
        .is_ok());

        // Neither the URL-safe alphabet nor missing padding decodes.
        let key = [0xfbu8; 16];
        assert!(base64_key(&key).contains('+'));
        for password in [
            base64::engine::general_purpose::URL_SAFE.encode(key),
            base64_key(&key).trim_end_matches('=').to_string(),
        ] {
            let error = load_error(&format!(
                "cipher: 2022-blake3-aes-128-gcm, password: '{password}'"
            ));
            assert!(
                error.starts_with(
                    "ss 1.2.3.4:8388 cipher: 2022-blake3-aes-128-gcm initialize error: decode key: "
                ),
                "{error}"
            );
        }

        let long_key = base64_key(&[9u8; 32]);
        assert_eq!(
            load_error(&format!(
                "cipher: 2022-blake3-aes-128-gcm, password: '{}:{long_key}'",
                encoded[0]
            )),
            "ss 1.2.3.4:8388 cipher: 2022-blake3-aes-128-gcm initialize error: \
             bad key length, required 16, got 32"
        );
        assert_eq!(
            load_error(&format!(
                "cipher: 2022-blake3-chacha20-poly1305, password: '{long_key}:{long_key}'"
            )),
            "ss 1.2.3.4:8388 cipher: 2022-blake3-chacha20-poly1305 initialize error: \
             Shadowsocks 2022 EIH support only available in AES ciphers"
        );
    }

    /// mihomo compat: NewShadowSocks walks an if/else-if chain over the
    /// plugin name with no final else (adapter/outbound/shadowsocks.go), so a
    /// name it does not know selects no plugin. The plugins it does know and
    /// that are not implemented here must not load as something else.
    #[test]
    fn ss_plugin_names_follow_mihomo() {
        for plugin in [
            "does-not-exist",
            "obfs-local",
            "simple-obfs",
            "shadowtls",
            "shadow-tls-v3",
        ] {
            let mut config = make_ss_config();
            config.plugin = Some(plugin.to_string());
            let outbound = ShadowsocksOutbound::from_config(&config).unwrap();
            assert!(matches!(outbound.plugin, Plugin::None), "{plugin}");
        }
        assert!(matches!(
            ShadowsocksOutbound::from_config(&make_ss_config())
                .unwrap()
                .plugin,
            Plugin::None
        ));

        for plugin in ["gost-plugin", "shadow-tls", "restls", "jls", "kcptun"] {
            let mut config = make_ss_config();
            config.plugin = Some(plugin.to_string());
            let err = match ShadowsocksOutbound::from_config(&config) {
                Ok(_) => panic!("plugin {plugin} must be rejected"),
                Err(e) => e.to_string(),
            };
            assert_eq!(
                err,
                format!("ss 1.2.3.4:8388 plugin {plugin} is not implemented")
            );
        }

        // shadow-tls is not implemented in any version.
        for version in [1, 2, 3] {
            assert!(load(&format!(
                "cipher: aes-256-gcm, password: p, plugin: shadow-tls, \
                 plugin-opts: {{host: example.com, password: p, version: {version}}}"
            ))
            .is_err());
        }
    }

    /// mihomo compat: `simpleObfsOption{Host: "bing.com"}`, and a mode that
    /// is neither `tls` nor `http` is `ss <addr> obfs mode error: <mode>`.
    #[test]
    fn ss_obfs_options_follow_mihomo() {
        let obfs = |opts: &str| format!("cipher: aes-256-gcm, password: p, plugin: obfs{opts}");

        assert_eq!(load_error(&obfs("")), "ss 1.2.3.4:8388 obfs mode error: ");
        assert_eq!(
            load_error(&obfs(", plugin-opts: {mode: quic}")),
            "ss 1.2.3.4:8388 obfs mode error: quic"
        );
        // The TLS mode's wire format is not implemented.
        assert_eq!(
            load_error(&obfs(", plugin-opts: {mode: tls}")),
            "ss 1.2.3.4:8388 obfs mode tls is not implemented"
        );

        let outbound = load(&obfs(", plugin-opts: {mode: http}")).unwrap();
        assert!(matches!(outbound.plugin, Plugin::ObfsHttp { host } if host == "bing.com"));
        let outbound = load(&obfs(", plugin-opts: {mode: http, host: example.com}")).unwrap();
        assert!(matches!(outbound.plugin, Plugin::ObfsHttp { host } if host == "example.com"));
    }

    /// mihomo compat: `v2rayObfsOption{Host: "bing.com", Mux: true}`, and a
    /// mode other than `websocket` is `ss <addr> obfs mode error: <mode>`.
    #[test]
    fn ss_v2ray_plugin_options_follow_mihomo() {
        let v2ray =
            |opts: &str| format!("cipher: aes-256-gcm, password: p, plugin: v2ray-plugin{opts}");

        assert_eq!(load_error(&v2ray("")), "ss 1.2.3.4:8388 obfs mode error: ");
        assert_eq!(
            load_error(&v2ray(", plugin-opts: {mode: quic, mux: false}")),
            "ss 1.2.3.4:8388 obfs mode error: quic"
        );
        // Mux is on by default, and neither it nor HTTP upgrade is implemented.
        assert_eq!(
            load_error(&v2ray(", plugin-opts: {mode: websocket}")),
            "ss 1.2.3.4:8388 v2ray-plugin mux is not implemented, set mux: false"
        );
        assert_eq!(
            load_error(&v2ray(
                ", plugin-opts: {mode: websocket, mux: false, v2ray-http-upgrade: true}"
            )),
            "ss 1.2.3.4:8388 v2ray-plugin v2ray-http-upgrade is not implemented"
        );

        let outbound = load(&v2ray(", plugin-opts: {mode: websocket, mux: false}")).unwrap();
        assert!(matches!(
            outbound.plugin,
            Plugin::V2ray { host, path, tls: false } if host == "bing.com" && path == "/"
        ));
        let outbound = load(&v2ray(
            ", plugin-opts: {mode: websocket, mux: false, host: example.com, path: /ws, tls: true}",
        ))
        .unwrap();
        assert!(matches!(
            outbound.plugin,
            Plugin::V2ray { host, path, tls: true } if host == "example.com" && path == "/ws"
        ));
    }

    /// mihomo compat: NewShadowSocks — an unset version is the legacy
    /// protocol, and one that is neither 1 nor 2 fails the load even with
    /// `udp-over-tcp` off.
    #[test]
    fn ss_udp_over_tcp_version_follows_mihomo() {
        let base = "cipher: aes-256-gcm, password: p, udp: true";
        let outbound = load(base).unwrap();
        assert!(!outbound.udp_over_tcp);
        assert_eq!(outbound.udp_over_tcp_version, 1);

        for (version, expected) in [(0, 1), (1, 1), (2, 2)] {
            let outbound = load(&format!(
                "{base}, udp-over-tcp: true, udp-over-tcp-version: {version}"
            ))
            .unwrap();
            assert!(outbound.udp_over_tcp);
            assert_eq!(outbound.udp_over_tcp_version, expected);
        }

        assert_eq!(
            load_error(&format!("{base}, udp-over-tcp-version: 3")),
            "ss 1.2.3.4:8388 unknown udp over tcp protocol version: 3"
        );
    }

    /// mihomo compat: `method.DialConn` writes the request while dialing
    /// (shadowsocks.go StreamConnContext), so the tunnel owes it at once.
    #[test]
    fn ss_request_header_is_owed_at_dial() {
        let outbound = ShadowsocksOutbound::from_config(&make_ss_config()).unwrap();
        assert_eq!(outbound.handshake(), Handshake::AtDial);
    }

    /// A TCP listener and a UDP socket on one loopback port, as a server has.
    async fn bind_server() -> (TcpListener, UdpSocket) {
        loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
                return (tcp, udp);
            }
        }
    }

    /// The shape of node this outbound mostly serves, end to end over
    /// loopback against the server side written out in `test_support`.
    #[tokio::test]
    async fn ss2022_node_relays_tcp_and_udp() {
        const METHOD: &str = "2022-blake3-aes-128-gcm";
        let psk: Vec<u8> = (0..16).collect();
        let (tcp, udp) = bind_server().await;
        let port = tcp.local_addr().unwrap().port();
        let config: ProxyConfig = serde_yaml::from_str(&format!(
            "{{name: n, type: ss, server: 127.0.0.1, port: {port}, cipher: {METHOD}, \
             password: \"{}\", udp: true}}",
            base64_key(&psk)
        ))
        .unwrap();
        let outbound = ShadowsocksOutbound::from_config(&config).unwrap();
        assert!(outbound.supports_udp());
        let dns = dns().await;
        let target = Address::domain("example.com", 443);
        let now = aead::unix_now();

        // TCP: the tunnel's empty write sends the request; the server speaks
        // first; then the payload goes both ways.
        let mut stream = outbound.connect_stream(&target, &dns).await.unwrap();
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        stream.flush().await.unwrap();
        let (mut peer, _) = tcp.accept().await.unwrap();
        let mut wire = vec![0u8; 16 + 27];
        peer.read_exact(&mut wire).await.unwrap();
        let session_key = blake3_subkey(SESSION_SUBKEY, &psk, &wire[..16]);
        let fixed = StreamKey::new(METHOD, &session_key).open(&wire[16..]);
        let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut variable = vec![0u8; variable_len + 16];
        peer.read_exact(&mut variable).await.unwrap();
        wire.extend(variable);
        let mut request = read_request_2022(METHOD, &[&psk], &wire);
        assert_eq!(request.target, encode_address(&target));
        assert!(request.timestamp.abs_diff(now) <= 1);

        let (response, mut response_key) = response_2022(
            METHOD,
            &psk,
            &[0x99; 16],
            &request.salt,
            now,
            b"220 ready\r\n",
        );
        peer.write_all(&response).await.unwrap();
        let mut banner = [0u8; 11];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"220 ready\r\n");

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut chunk = [0u8; 18 + 4 + 16];
        peer.read_exact(&mut chunk).await.unwrap();
        assert_eq!(request.key.open_chunks(&chunk), b"ping");
        peer.write_all(&response_key.seal_chunk(b"pong"))
            .await
            .unwrap();
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");

        // UDP: SIP022 packets to the same port, to whatever destination each
        // datagram names; a reply is reported from the source it names.
        let first = Address::ip("93.184.216.34:443".parse().unwrap());
        let second = Address::ip("[2001:db8::1]:53".parse().unwrap());
        let packets = outbound.connect_datagram(&first, dns).await.unwrap();
        let server = UdpServer2022::new(METHOD, &[&psk], 0x0102_0304_0506_0708);
        let mut datagram = [0u8; 2048];
        for (packet_id, destination) in [&first, &second, &first].into_iter().enumerate() {
            let query = format!("query {packet_id}");
            assert_eq!(
                packets
                    .send_to(query.as_bytes(), destination)
                    .await
                    .unwrap(),
                query.len()
            );
            let (n, client) = udp.recv_from(&mut datagram).await.unwrap();
            let packet = server.open(&datagram[..n]);
            assert_eq!(packet.packet_id, packet_id as u64);
            assert_eq!(packet.target, encode_address(destination));
            assert_eq!(packet.data, query.as_bytes());
            assert!(packet.timestamp.abs_diff(now) <= 1);

            let reply = server.seal(
                packet_id as u64,
                packet.session_id,
                now,
                0,
                &packet.target,
                b"answer",
            );
            udp.send_to(&reply, client).await.unwrap();
            let mut answer = [0u8; 64];
            let (n, from) = packets.recv_from(&mut answer).await.unwrap();
            assert_eq!(&answer[..n], b"answer");
            assert_eq!(&from, destination);
        }
    }

    #[tokio::test]
    async fn ss_udp_needs_the_udp_option() {
        let outbound = load("cipher: aes-256-gcm, password: p").unwrap();
        assert!(!outbound.supports_udp());
        let target = Address::ip("1.1.1.1:53".parse().unwrap());
        assert!(outbound
            .connect_datagram(&target, dns().await)
            .await
            .is_err());
    }

    /// mihomo compat: with `udp-over-tcp` the packets ride a stream opened to
    /// the UoT magic address (shadowsocks.go ListenPacketContext,
    /// StreamConnContext). Under `none` the stream is plain, so the server
    /// sees the Shadowsocks address and the UoT framing as they are.
    #[tokio::test]
    async fn ss_udp_over_tcp_frames_packets_on_a_stream() {
        for (version, magic) in [(1, "sp.udp-over-tcp.arpa"), (2, "sp.v2.udp-over-tcp.arpa")] {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = tcp.local_addr().unwrap().port();
            let config: ProxyConfig = serde_yaml::from_str(&format!(
                "{{name: n, type: ss, server: 127.0.0.1, port: {port}, cipher: none, \
                 password: '', udp: true, udp-over-tcp: true, udp-over-tcp-version: {version}}}"
            ))
            .unwrap();
            let outbound = ShadowsocksOutbound::from_config(&config).unwrap();
            let target = Address::ip("9.9.9.9:853".parse().unwrap());
            let packets = outbound
                .connect_datagram(&target, dns().await)
                .await
                .unwrap();

            // The request header is there before any packet is sent.
            let (mut peer, _) = tcp.accept().await.unwrap();
            let mut request = vec![3, magic.len() as u8];
            request.extend_from_slice(magic.as_bytes());
            request.extend_from_slice(&[0, 0]);
            let mut wire = vec![0u8; request.len()];
            peer.read_exact(&mut wire).await.unwrap();
            assert_eq!(wire, request, "v{version}");

            packets.send_to(b"query", &target).await.unwrap();
            let other = Address::ip("1.1.1.1:53".parse().unwrap());
            packets.send_to(b"second", &other).await.unwrap();
            let mut expected = Vec::new();
            if version == 2 {
                // The version 2 request: not connect mode, then the
                // destination the connection was dialed for.
                expected.extend_from_slice(&[0, 1, 9, 9, 9, 9, 3, 85]);
            }
            expected.extend_from_slice(&[0, 9, 9, 9, 9, 3, 85, 0, 5]);
            expected.extend_from_slice(b"query");
            expected.extend_from_slice(&[0, 1, 1, 1, 1, 0, 53, 0, 6]);
            expected.extend_from_slice(b"second");
            let mut wire = vec![0u8; expected.len()];
            peer.read_exact(&mut wire).await.unwrap();
            assert_eq!(wire, expected, "v{version}");

            peer.write_all(&[0, 8, 8, 4, 4, 0, 53, 0, 6]).await.unwrap();
            peer.write_all(b"answer").await.unwrap();
            let mut answer = [0u8; 64];
            let (n, from) = packets.recv_from(&mut answer).await.unwrap();
            assert_eq!(&answer[..n], b"answer", "v{version}");
            assert_eq!(from, Address::ip("8.8.4.4:53".parse().unwrap()));
        }
    }
}
