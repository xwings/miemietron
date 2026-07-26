//! Shared transport stack for the adapters that layer a protocol header over
//! an interchangeable transport chain: VMess, VLESS and Trojan.
//!
//! All three build the same two-layer chain — an optional security layer (TLS
//! or Reality) with an optional application transport (WebSocket, gRPC, H2,
//! XHTTP) on top — and then wrap the result in their own protocol stream. They
//! used to each spell that chain out as a `match self.network.as_str()` nested
//! inside a Reality-vs-TLS branch, ~10 near-identical arms per adapter.
//!
//! What stays per-adapter is the *decision*: which ALPN each network implies,
//! and whether TLS applies at all. Those rules differ between the three (see
//! `security_for` in each adapter) and each divergence is a documented mihomo
//! quirk, so this module only applies the [`SecuritySpec`] it is handed.
//!
//! The chain is modelled as nested enums rather than `Box<dyn>` so every read
//! and write stays statically dispatched — the relay already pays one vtable
//! hop through `Box<dyn ProxyStream>`, and there is no reason to add a second
//! one per layer.

use anyhow::{Context, Result};
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_rustls::client::TlsStream;

use super::grpc::{self, GrpcStream};
use super::h2_transport::{self, H2Stream};
use super::reality::{self, RealityConfig};
use super::tls::{self, TlsOptions};
use super::ws::{self, WsOptions, WsStream};
use super::xhttp::{self, XHttpConfig};

/// Generate `AsyncRead` + `AsyncWrite` for an enum whose every variant holds
/// one stream, by delegating to the active variant.
///
/// `poll_write_vectored` / `is_write_vectored` are delegated too: `TlsStream`
/// implements them, and swallowing that would quietly turn one vectored write
/// into several plain ones.
macro_rules! delegate_io {
    ($enum:ident, $($variant:ident),+ $(,)?) => {
        impl<S> AsyncRead for $enum<S>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $($enum::$variant(s) => Pin::new(s).poll_read(cx, buf),)+
                }
            }
        }

        impl<S> AsyncWrite for $enum<S>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                match self.get_mut() {
                    $($enum::$variant(s) => Pin::new(s).poll_write(cx, buf),)+
                }
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                match self.get_mut() {
                    $($enum::$variant(s) => Pin::new(s).poll_write_vectored(cx, bufs),)+
                }
            }

            fn is_write_vectored(&self) -> bool {
                match self {
                    $($enum::$variant(s) => s.is_write_vectored(),)+
                }
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $($enum::$variant(s) => Pin::new(s).poll_flush(cx),)+
                }
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $($enum::$variant(s) => Pin::new(s).poll_shutdown(cx),)+
                }
            }
        }
    };
}

/// The stream after the optional security layer.
///
/// `clippy::large_enum_variant` fires here because a rustls `TlsStream` is far
/// larger than a bare `TcpStream`. Boxing it would put a heap indirection on
/// every read and write, which is the one thing this module exists to avoid —
/// and it would not save anything in practice, since the whole chain already
/// lands inside the single `Box<dyn ProxyStream>` the adapter returns.
#[allow(clippy::large_enum_variant)]
pub enum Secured<S> {
    Plain(S),
    /// TLS — and Reality, which produces the same `TlsStream`: Reality's
    /// authentication rides in the ClientHello session ID, so once the
    /// handshake completes there is nothing protocol-specific left in the
    /// stream (`transport/reality.rs`).
    Tls(TlsStream<S>),
}

delegate_io!(Secured, Plain, Tls);

/// The stream after the optional application-layer transport.
pub enum Layered<S> {
    Plain(S),
    Ws(WsStream<S>),
    Grpc(GrpcStream),
    H2(H2Stream),
    Xhttp(DuplexStream),
}

delegate_io!(Layered, Plain, Ws, Grpc, H2, Xhttp);

/// Which security layer, if any, the transport chain runs over.
pub enum SecuritySpec {
    /// Plain TCP. VMess and VLESS reach this when `tls: false`; Trojan never
    /// does (the protocol mandates TLS).
    None,
    Tls(TlsOptions),
    Reality(RealityConfig),
}

/// The application transport to layer on top of the security layer, already
/// resolved from the adapter's `network` plus its `*-opts` block.
///
/// Built by [`transport_kind`] so only the options the active network actually
/// uses get allocated per dial.
pub enum TransportKind {
    /// No application transport — the config's `tcp` (or any unknown value,
    /// matching the `default:` arm of mihomo's `StreamConnContext` switch).
    Plain,
    Ws(WsOptions),
    Grpc {
        service: String,
        /// The `:authority` header — the adapter's effective SNI.
        authority: String,
    },
    H2 {
        host: String,
        path: String,
    },
    /// Boxed because `XHttpConfig` is an order of magnitude larger than any
    /// other variant, and this enum is moved once per dial.
    Xhttp(Box<XHttpConfig>),
}

/// Everything [`wrap_transport`] needs, assembled by the calling adapter.
pub struct TransportSpec {
    /// Adapter name for the error context — `"VMess"`, `"VLESS"`, `"Trojan"`.
    pub label: &'static str,
    pub security: SecuritySpec,
    pub transport: TransportKind,
}

/// Build the security + transport chain over an already-connected stream.
///
/// The protocol header is *not* written here — the caller wraps the result in
/// its own `VmessStream` / `VlessStream` / `TrojanStream`.
pub async fn wrap_transport<S>(stream: S, spec: TransportSpec) -> Result<Layered<Secured<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let label = spec.label;
    // Kept because the old per-branch messages distinguished a failure over
    // Reality from one over plain TLS, which is worth knowing when debugging a
    // camouflaged handshake.
    let via = match spec.security {
        SecuritySpec::Reality(_) => " over Reality",
        _ => "",
    };

    let secured = match spec.security {
        SecuritySpec::None => Secured::Plain(stream),
        SecuritySpec::Tls(ref opts) => Secured::Tls(
            tls::wrap_tls(stream, opts)
                .await
                .with_context(|| format!("{label}: TLS handshake failed"))?,
        ),
        SecuritySpec::Reality(ref config) => Secured::Tls(
            reality::wrap_reality(stream, config)
                .await
                .with_context(|| format!("{label}: Reality handshake failed"))?,
        ),
    };

    Ok(match spec.transport {
        TransportKind::Plain => Layered::Plain(secured),
        TransportKind::Ws(opts) => Layered::Ws(
            ws::wrap_ws(secured, &opts)
                .await
                .with_context(|| format!("{label}: WebSocket upgrade{via} failed"))?,
        ),
        TransportKind::Grpc { service, authority } => Layered::Grpc(
            grpc::connect_grpc(secured, &service, &authority)
                .await
                .with_context(|| format!("{label}: gRPC connect{via} failed"))?,
        ),
        TransportKind::H2 { host, path } => Layered::H2(
            h2_transport::connect_h2(secured, &host, &path)
                .await
                .with_context(|| format!("{label}: H2 connect{via} failed"))?,
        ),
        TransportKind::Xhttp(config) => Layered::Xhttp(
            xhttp::connect_h2(secured, *config)
                .await
                .with_context(|| format!("{label}: XHTTP connect{via} failed"))?,
        ),
    })
}

/// Resolve `network` plus the adapter's transport option blocks into the
/// transport to layer on. `sni` is the adapter's effective SNI, which supplies
/// the default WS host, H2 host and gRPC authority.
///
/// `xhttp` is the already-normalized config an adapter built at load time
/// (`XHttpConfig::from_options`); VMess and Trojan have no XHTTP path and pass
/// `None`.
pub fn transport_kind(
    network: &str,
    sni: &str,
    ws_opts: Option<&crate::config::proxy::WsOpts>,
    grpc_opts: Option<&crate::config::proxy::GrpcOpts>,
    h2_opts: Option<&crate::config::proxy::H2Opts>,
    xhttp: Option<&XHttpConfig>,
) -> Result<TransportKind> {
    Ok(match network {
        "ws" => TransportKind::Ws(ws_options(ws_opts, sni)),
        "grpc" => TransportKind::Grpc {
            // mihomo compat: the gRPC service name defaults to `GunService`
            // (`transport/gun/gun.go`).
            service: grpc_opts
                .and_then(|o| o.grpc_service_name.clone())
                .unwrap_or_else(|| "GunService".to_string()),
            authority: sni.to_string(),
        },
        "h2" => TransportKind::H2 {
            host: h2_opts
                .and_then(|o| o.host.first().cloned())
                .unwrap_or_else(|| sni.to_string()),
            path: h2_opts
                .and_then(|o| o.path.clone())
                .unwrap_or_else(|| "/".to_string()),
        },
        "xhttp" => TransportKind::Xhttp(Box::new(
            xhttp
                .context("XHTTP: missing normalized configuration")?
                .clone(),
        )),
        _ => TransportKind::Plain,
    })
}

/// Base TLS options from an adapter's config fields. Callers override the ALPN
/// where the transport dictates one.
pub fn tls_options(
    sni: &str,
    skip_cert_verify: bool,
    alpn: &[String],
    fingerprint: Option<&str>,
) -> TlsOptions {
    TlsOptions {
        sni: sni.to_string(),
        skip_cert_verify,
        alpn: alpn.to_vec(),
        fingerprint: fingerprint.map(str::to_string),
    }
}

/// WebSocket options, with a `Host` header in `ws-opts` overriding the SNI as
/// the WS host.
fn ws_options(opts: Option<&crate::config::proxy::WsOpts>, sni: &str) -> WsOptions {
    let mut ws_options = WsOptions {
        host: sni.to_string(),
        path: "/".to_string(),
        headers: Vec::new(),
    };

    if let Some(opts) = opts {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::{GrpcOpts, H2Opts, WsOpts};

    fn kind(network: &str) -> TransportKind {
        transport_kind(network, "sni.example.com", None, None, None, None).unwrap()
    }

    #[test]
    fn grpc_service_name_defaults_to_gunservice() {
        match kind("grpc") {
            TransportKind::Grpc { service, authority } => {
                assert_eq!(service, "GunService");
                assert_eq!(authority, "sni.example.com");
            }
            _ => panic!("expected gRPC"),
        }

        let opts = GrpcOpts {
            grpc_service_name: Some("Tun".to_string()),
            ..Default::default()
        };
        match transport_kind("grpc", "sni.example.com", None, Some(&opts), None, None).unwrap() {
            TransportKind::Grpc { service, .. } => assert_eq!(service, "Tun"),
            _ => panic!("expected gRPC"),
        }
    }

    #[test]
    fn h2_falls_back_to_sni_and_root() {
        match kind("h2") {
            TransportKind::H2 { host, path } => {
                assert_eq!(host, "sni.example.com");
                assert_eq!(path, "/");
            }
            _ => panic!("expected H2"),
        }

        let opts = H2Opts {
            host: vec!["a.example.com".to_string(), "b.example.com".to_string()],
            path: Some("/p".to_string()),
        };
        match transport_kind("h2", "sni.example.com", None, None, Some(&opts), None).unwrap() {
            TransportKind::H2 { host, path } => {
                assert_eq!(host, "a.example.com");
                assert_eq!(path, "/p");
            }
            _ => panic!("expected H2"),
        }
    }

    #[test]
    fn ws_host_header_overrides_the_sni() {
        let opts = WsOpts {
            path: Some("/ws".to_string()),
            headers: vec![("Host".to_string(), "cdn.example.com".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        match transport_kind("ws", "sni.example.com", Some(&opts), None, None, None).unwrap() {
            TransportKind::Ws(ws) => {
                assert_eq!(ws.host, "cdn.example.com");
                assert_eq!(ws.path, "/ws");
                assert_eq!(
                    ws.headers,
                    vec![("Host".to_string(), "cdn.example.com".to_string())]
                );
            }
            _ => panic!("expected WS"),
        }
    }

    #[test]
    fn ws_defaults_to_sni_and_root_without_opts() {
        match kind("ws") {
            TransportKind::Ws(ws) => {
                assert_eq!(ws.host, "sni.example.com");
                assert_eq!(ws.path, "/");
                assert!(ws.headers.is_empty());
            }
            _ => panic!("expected WS"),
        }
    }

    #[test]
    fn tcp_and_unknown_networks_are_plain() {
        assert!(matches!(kind("tcp"), TransportKind::Plain));
        assert!(matches!(kind("http"), TransportKind::Plain));
    }

    #[test]
    fn xhttp_without_a_normalized_config_is_an_error() {
        let error = transport_kind("xhttp", "sni.example.com", None, None, None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("missing normalized configuration"));
    }
}
