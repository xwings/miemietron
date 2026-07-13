//! SSR obfuscation plugins.
//!
//! Obfuscation wraps the encrypted SSR stream to disguise traffic as other
//! protocols. On the wire the obfs framing is the OUTERMOST layer: mihomo
//! applies `cipher.StreamConn` first and `obfs.StreamConn` closest to the
//! socket, so the obfs header bytes appear as plaintext on the wire wrapping
//! the already-ciphered payload (see `adapter/outbound/shadowsocksr.go`
//! `StreamConnContext`).
//!
//! Parity policy (see CLAUDE.md "never silent fallback"):
//! - `plain`: fully implemented (passthrough, `plain.StreamConn` returns the
//!   conn unchanged).
//! - Every other name mihomo recognizes (`http_simple`, `http_post`,
//!   `random_head`, `tls1.2_ticket_auth`, `tls1.2_ticket_fastauth`) is
//!   RECOGNIZED so `from_name` distinguishes "typo" from
//!   "known-but-unimplemented", but is reported as NOT implemented.
//!   `SsrOutbound::from_config` turns that into a hard config-load error.
//!
//! mihomo compat: mihomo implements all of these. Two reasons we fail loud
//! instead of shipping them:
//!   1. The previous hand-rolled `http_simple` writer diverged materially from
//!      `obfs/http_simple.go` (wrong header layout, no URL-encoded head data,
//!      no `IVSize+30` head split, invented `Content-Length`).
//!   2. miemietron's SSR pipeline currently nests obfs OUTSIDE the stream
//!      cipher (`mod.rs`), the inverse of mihomo, so any obfs that injects
//!      plaintext framing (http_*, tls1.2_*) would have that framing encrypted
//!      by the cipher and corrupted on the wire. Until the nesting is
//!      corrected these cannot be shipped correctly, so we reject them at load
//!      rather than silently produce a broken connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Supported SSR obfuscation plugin types.
///
/// All variants mihomo recognizes are represented so an unknown name is
/// distinguishable from a known-but-unimplemented one. Only `Plain` is wired
/// on the data path; the rest are rejected at config load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrObfs {
    Plain,
    HttpSimple,
    HttpPost,
    RandomHead,
    Tls12TicketAuth,
    Tls12TicketFastauth,
}

impl SsrObfs {
    /// Parse obfs plugin name from config string.
    ///
    /// Returns `None` only for names mihomo itself would reject with
    /// `Obfs <name> not supported`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "plain" | "" => Some(SsrObfs::Plain),
            "http_simple" | "http-simple" => Some(SsrObfs::HttpSimple),
            "http_post" | "http-post" => Some(SsrObfs::HttpPost),
            "random_head" | "random-head" => Some(SsrObfs::RandomHead),
            "tls1.2_ticket_auth" | "tls12_ticket_auth" | "tls1.2-ticket-auth" => {
                Some(SsrObfs::Tls12TicketAuth)
            }
            "tls1.2_ticket_fastauth" | "tls12_ticket_fastauth" | "tls1.2-ticket-fastauth" => {
                Some(SsrObfs::Tls12TicketFastauth)
            }
            _ => None,
        }
    }

    /// Canonical mihomo name, used in error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            SsrObfs::Plain => "plain",
            SsrObfs::HttpSimple => "http_simple",
            SsrObfs::HttpPost => "http_post",
            SsrObfs::RandomHead => "random_head",
            SsrObfs::Tls12TicketAuth => "tls1.2_ticket_auth",
            SsrObfs::Tls12TicketFastauth => "tls1.2_ticket_fastauth",
        }
    }

    /// Whether this obfs is actually implemented on the data path.
    ///
    /// Anything returning `false` here is rejected at config load rather than
    /// silently degraded to `plain`.
    pub fn is_implemented(&self) -> bool {
        matches!(self, SsrObfs::Plain)
    }
}

/// SSR obfuscation stream wrapper.
///
/// Only ever constructed for `plain` (all other obfs are rejected at config
/// load), so this is a transparent passthrough matching mihomo's
/// `plain.StreamConn`, which returns the connection unchanged.
pub struct SsrObfsStream<T> {
    inner: T,
}

impl<T> SsrObfsStream<T> {
    /// Create a new SSR obfuscation stream.
    ///
    /// Callers MUST have validated `obfs.is_implemented()` at config load;
    /// only `plain` reaches this point.
    pub fn new(inner: T, obfs: SsrObfs, _param: &str) -> Self {
        debug_assert!(
            obfs.is_implemented(),
            "SsrObfsStream constructed with unimplemented obfs {obfs:?}; \
             SsrOutbound::from_config must reject it at load"
        );
        Self { inner }
    }
}

impl<T: AsyncRead + Unpin + Send> AsyncRead for SsrObfsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // plain: direct passthrough.
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + Send> AsyncWrite for SsrObfsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfs_from_name_recognizes_all_mihomo_names() {
        assert_eq!(SsrObfs::from_name("plain"), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_name(""), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_name("http_simple"), Some(SsrObfs::HttpSimple));
        assert_eq!(SsrObfs::from_name("http_post"), Some(SsrObfs::HttpPost));
        assert_eq!(SsrObfs::from_name("random_head"), Some(SsrObfs::RandomHead));
        assert_eq!(
            SsrObfs::from_name("tls1.2_ticket_auth"),
            Some(SsrObfs::Tls12TicketAuth)
        );
        assert_eq!(
            SsrObfs::from_name("tls1.2_ticket_fastauth"),
            Some(SsrObfs::Tls12TicketFastauth)
        );
        // Unknown name → None (mihomo: "Obfs <name> not supported").
        assert_eq!(SsrObfs::from_name("unknown_obfs"), None);
    }

    #[test]
    fn only_plain_is_implemented() {
        assert!(SsrObfs::Plain.is_implemented());
        assert!(!SsrObfs::HttpSimple.is_implemented());
        assert!(!SsrObfs::HttpPost.is_implemented());
        assert!(!SsrObfs::RandomHead.is_implemented());
        assert!(!SsrObfs::Tls12TicketAuth.is_implemented());
        assert!(!SsrObfs::Tls12TicketFastauth.is_implemented());
    }
}
