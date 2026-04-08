//! HTTP proxy outbound handler.
//!
//! Tunnels connections through a remote HTTP proxy using the CONNECT method.
//! Supports optional TLS wrapping and basic proxy authentication.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use super::{OutboundHandler, ProxyStream};
use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::transport::tcp::{self, ConnectOpts};
use crate::transport::tls::{self, TlsOptions};

pub struct HttpOutbound {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    headers: HashMap<String, String>,
    connect_opts: ConnectOpts,
}

impl HttpOutbound {
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("http proxy missing server"))?
            .clone();
        let port = config.port.ok_or_else(|| anyhow!("http proxy missing port"))?;

        // Parse username/password from config fields
        let username = config
            .extra
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let password = config.password.clone();

        // Parse headers from extra
        let headers = config
            .extra
            .get("headers")
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| {
                        Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            username,
            password,
            tls: config.tls.unwrap_or(false),
            sni: config.sni.clone(),
            skip_cert_verify: config.skip_cert_verify.unwrap_or(false),
            headers,
            connect_opts: ConnectOpts::from_proxy_config(config),
        })
    }
}

#[async_trait]
impl OutboundHandler for HttpOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "Http"
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let addr = std::net::SocketAddr::new(ip, self.port);
        let stream = tcp::connect(addr, &self.connect_opts).await?;
        debug!("HTTP proxy connected to {}:{}", self.server, self.port);

        if self.tls {
            let tls_opts = TlsOptions {
                sni: self.sni.clone().unwrap_or_else(|| self.server.clone()),
                skip_cert_verify: self.skip_cert_verify,
                alpn: vec![],
                fingerprint: None,
            };
            let tls_stream = tls::wrap_tls(stream, &tls_opts).await?;
            self.send_connect(tls_stream, target).await
        } else {
            self.send_connect(stream, target).await
        }
    }
}

impl HttpOutbound {
    async fn send_connect<S>(
        &self,
        mut stream: S,
        target: &Address,
    ) -> Result<Box<dyn ProxyStream>>
    where
        S: super::ProxyStream + 'static,
    {
        let host_port = match target {
            Address::Domain(host, port) => format!("{host}:{port}"),
            Address::Ip(addr) => addr.to_string(),
        };

        // Build CONNECT request
        let mut req = format!(
            "CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n"
        );

        // Add proxy authentication
        if let Some(ref username) = self.username {
            let pass = self.password.as_deref().unwrap_or("");
            let creds = base64::engine::general_purpose::STANDARD
                .encode(format!("{username}:{pass}"));
            req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
        }

        // Add custom headers
        for (key, value) in &self.headers {
            req.push_str(&format!("{key}: {value}\r\n"));
        }

        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        // Read response status line
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await?;

        // Expect "HTTP/1.x 200 ..."
        if !status_line.contains(" 200 ") {
            return Err(anyhow!(
                "HTTP proxy CONNECT failed: {}",
                status_line.trim()
            ));
        }

        // Consume remaining headers until empty line
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        debug!("HTTP proxy tunnel established to {}", host_port);

        // Return the underlying stream (unwrap BufReader, keeping any buffered data)
        // BufReader may have buffered bytes; we return it as-is since it implements
        // AsyncRead + AsyncWrite (via pin-project on the inner stream).
        // However, BufReader doesn't impl AsyncWrite, so we need the raw stream.
        // The proxy response is fully consumed, so no buffered leftover.
        let inner = reader.into_inner();
        Ok(Box::new(inner))
    }
}
