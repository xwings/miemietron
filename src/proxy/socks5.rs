//! SOCKS5 proxy outbound handler.
//!
//! Tunnels connections through a remote SOCKS5 proxy server.
//! Supports no-auth and username/password authentication (RFC 1928 / RFC 1929).
//! Optional TLS wrapping for SOCKS5 over TLS.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use super::{OutboundHandler, ProxyStream};
use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

pub struct Socks5Outbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    udp: bool,
    connect_opts: ConnectOpts,
}

impl Socks5Outbound {
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("socks5 proxy missing server"))?
            .clone();
        let port = config
            .port
            .ok_or_else(|| anyhow!("socks5 proxy missing port"))?;

        let username = config
            .extra
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let password = config.password.clone();

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            username,
            password,
            tls: config.tls.unwrap_or(false),
            sni: config.sni.clone(),
            skip_cert_verify: config.skip_cert_verify.unwrap_or(false),
            udp: config.udp.unwrap_or(false),
            connect_opts: ConnectOpts::from_proxy_config(config),
        })
    }
}

#[async_trait]
impl OutboundHandler for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "Socks5"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let addr = std::net::SocketAddr::new(ip, self.port);
        let stream = tcp::connect(addr, &self.connect_opts).await?;
        debug!("SOCKS5 connected to {}:{}", self.server, self.port);

        if self.tls {
            let tls_opts = TlsOptions {
                sni: self.sni.clone().unwrap_or_else(|| self.server.clone()),
                skip_cert_verify: self.skip_cert_verify,
                alpn: vec![],
                fingerprint: None,
            };
            let tls_stream = tls::wrap_tls(stream, &tls_opts).await?;
            self.socks5_handshake(tls_stream, target).await
        } else {
            self.socks5_handshake(stream, target).await
        }
    }
}

impl Socks5Outbound {
    async fn socks5_handshake<S>(
        &self,
        mut stream: S,
        target: &Address,
    ) -> Result<Box<dyn ProxyStream>>
    where
        S: ProxyStream + 'static,
    {
        let has_auth = self.username.is_some();
        if has_auth {
            // Offer both no-auth and user/pass
            stream
                .write_all(&[SOCKS5_VERSION, 2, AUTH_NONE, AUTH_USER_PASS])
                .await?;
        } else {
            stream
                .write_all(&[SOCKS5_VERSION, 1, AUTH_NONE])
                .await?;
        }
        stream.flush().await?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;

        if resp[0] != SOCKS5_VERSION {
            return Err(anyhow!("SOCKS5 server returned invalid version: {}", resp[0]));
        }

        match resp[1] {
            AUTH_NONE => {} // No auth needed
            AUTH_USER_PASS => {
                // RFC 1929 sub-negotiation
                let user = self
                    .username
                    .as_ref()
                    .ok_or_else(|| anyhow!("SOCKS5 server requires auth but no username set"))?;
                let pass = self.password.as_deref().unwrap_or("");

                let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                auth_req.push(0x01); // sub-negotiation version
                auth_req.push(user.len() as u8);
                auth_req.extend_from_slice(user.as_bytes());
                auth_req.push(pass.len() as u8);
                auth_req.extend_from_slice(pass.as_bytes());

                stream.write_all(&auth_req).await?;
                stream.flush().await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(anyhow!("SOCKS5 authentication failed (status: {})", auth_resp[1]));
                }
            }
            AUTH_NO_ACCEPTABLE => {
                return Err(anyhow!("SOCKS5 server: no acceptable auth methods"));
            }
            other => {
                return Err(anyhow!("SOCKS5 server chose unsupported auth method: {other}"));
            }
        }

        let mut connect_req = Vec::with_capacity(64);
        connect_req.extend_from_slice(&[SOCKS5_VERSION, CMD_CONNECT, 0x00]); // ver, cmd, rsv

        match target {
            Address::Domain(host, port) => {
                connect_req.push(ATYP_DOMAIN);
                connect_req.push(host.len() as u8);
                connect_req.extend_from_slice(host.as_bytes());
                connect_req.extend_from_slice(&port.to_be_bytes());
            }
            Address::Ip(sockaddr) => match sockaddr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    connect_req.push(ATYP_IPV4);
                    connect_req.extend_from_slice(&ipv4.octets());
                    connect_req.extend_from_slice(&sockaddr.port().to_be_bytes());
                }
                std::net::IpAddr::V6(ipv6) => {
                    connect_req.push(ATYP_IPV6);
                    connect_req.extend_from_slice(&ipv6.octets());
                    connect_req.extend_from_slice(&sockaddr.port().to_be_bytes());
                }
            },
        }

        stream.write_all(&connect_req).await?;
        stream.flush().await?;

        let mut reply_head = [0u8; 4];
        stream.read_exact(&mut reply_head).await?;

        if reply_head[0] != SOCKS5_VERSION {
            return Err(anyhow!("SOCKS5 reply invalid version: {}", reply_head[0]));
        }
        if reply_head[1] != REP_SUCCESS {
            return Err(anyhow!("SOCKS5 CONNECT failed with reply code: {}", reply_head[1]));
        }

        // Consume bound address (we don't need it, but must read it)
        match reply_head[3] {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2]; // 4 bytes IP + 2 bytes port
                stream.read_exact(&mut buf).await?;
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2]; // 16 bytes IP + 2 bytes port
                stream.read_exact(&mut buf).await?;
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize + 2]; // domain + 2 bytes port
                stream.read_exact(&mut buf).await?;
            }
            other => {
                return Err(anyhow!("SOCKS5 reply has unknown ATYP: {other}"));
            }
        }

        debug!(
            "SOCKS5 tunnel established through {}:{} to {}",
            self.server,
            self.port,
            match target {
                Address::Domain(h, p) => format!("{h}:{p}"),
                Address::Ip(a) => a.to_string(),
            }
        );

        Ok(Box::new(stream))
    }
}
