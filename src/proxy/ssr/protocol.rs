//! SSR protocol plugins.
//!
//! Protocol plugins modify the SSR stream *between* the stream cipher and the
//! obfuscation layer. They add authentication or packet framing beyond what
//! the base SS protocol provides.
//!
//! Supported plugins:
//! - `origin`: No modification (passthrough, same as plain Shadowsocks).
//! - `auth_aes128_md5`, `auth_aes128_sha1`: Placeholder (falls back to origin with a warning).
//! - `auth_chain_a`, `auth_chain_b`: Placeholder (falls back to origin with a warning).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

// ---------------------------------------------------------------------------
// Protocol plugin type
// ---------------------------------------------------------------------------

/// Supported SSR protocol plugin types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrProtocol {
    Origin,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
}

impl SsrProtocol {
    /// Parse protocol plugin name from config string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "origin" | "" => Some(SsrProtocol::Origin),
            "auth_aes128_md5" | "auth-aes128-md5" => Some(SsrProtocol::AuthAes128Md5),
            "auth_aes128_sha1" | "auth-aes128-sha1" => Some(SsrProtocol::AuthAes128Sha1),
            "auth_chain_a" | "auth-chain-a" => Some(SsrProtocol::AuthChainA),
            "auth_chain_b" | "auth-chain-b" => Some(SsrProtocol::AuthChainB),
            _ => None,
        }
    }

    /// Whether this protocol is implemented (vs. stub/fallback).
    pub fn is_implemented(&self) -> bool {
        matches!(self, SsrProtocol::Origin)
    }
}

// ---------------------------------------------------------------------------
// SsrProtocolStream: wraps a stream with SSR protocol plugin
// ---------------------------------------------------------------------------

/// SSR protocol plugin stream wrapper.
///
/// Currently only `origin` is implemented. All other protocol plugins
/// fall back to `origin` (passthrough) with a warning logged.
///
/// This is a transparent wrapper — for `origin`, it simply delegates all
/// reads and writes to the inner stream without modification.
pub struct SsrProtocolStream<T> {
    inner: T,
    protocol: SsrProtocol,
}

impl<T: Unpin> Unpin for SsrProtocolStream<T> {}

impl<T> SsrProtocolStream<T> {
    /// Create a new SSR protocol stream.
    ///
    /// - `protocol`: the protocol plugin type.
    /// - `_param`: the protocol-param (reserved for future auth plugins).
    pub fn new(inner: T, protocol: SsrProtocol, _param: &str) -> Self {
        if !protocol.is_implemented() {
            warn!(
                "ssr: protocol plugin '{:?}' not yet implemented, falling back to origin (passthrough)",
                protocol
            );
        }

        Self { inner, protocol }
    }

    /// Get the effective protocol type (for diagnostics).
    pub fn protocol(&self) -> SsrProtocol {
        self.protocol
    }
}

// ---------------------------------------------------------------------------
// AsyncRead: passthrough (origin protocol = no modification)
// ---------------------------------------------------------------------------

impl<T: AsyncRead + Unpin + Send> AsyncRead for SsrProtocolStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Origin protocol: direct passthrough.
        // Other protocols: also passthrough for now (with warning already logged in constructor).
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

// ---------------------------------------------------------------------------
// AsyncWrite: passthrough (origin protocol = no modification)
// ---------------------------------------------------------------------------

impl<T: AsyncWrite + Unpin + Send> AsyncWrite for SsrProtocolStream<T> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_from_name() {
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
    fn origin_is_implemented() {
        assert!(SsrProtocol::Origin.is_implemented());
        assert!(!SsrProtocol::AuthAes128Md5.is_implemented());
        assert!(!SsrProtocol::AuthChainA.is_implemented());
    }
}
