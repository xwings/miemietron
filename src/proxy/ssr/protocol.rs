//! SSR protocol plugins.
//!
//! Protocol plugins modify the SSR stream *between* the stream cipher and the
//! obfuscation layer. They add authentication or packet framing beyond what
//! the base SS protocol provides.
//!
//! Parity policy (see CLAUDE.md "never silent fallback"):
//! - `origin`: fully implemented (passthrough, same as plain Shadowsocks).
//! - Every other name mihomo recognizes (`auth_sha1_v4`, `auth_aes128_md5`,
//!   `auth_aes128_sha1`, `auth_chain_a`, `auth_chain_b`) is RECOGNIZED so that
//!   `from_name` distinguishes "typo" from "known-but-unimplemented", but is
//!   reported as NOT implemented. `SsrOutbound::from_config` turns that into a
//!   hard config-load error instead of silently degrading to passthrough.
//!
//! mihomo compat: mihomo implements all of these. We deliberately fail loud
//! rather than ship a byte-inexact port of the per-packet HMAC auth framing
//! that cannot be verified against a live server. Failing at config load
//! honours the "never silent fallback to DIRECT/plain" rule.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Supported SSR protocol plugin types.
///
/// All variants mihomo recognizes are represented so that an unknown name is
/// distinguishable from a known-but-unimplemented one. Only `Origin` is wired
/// on the data path; the rest are rejected at config load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrProtocol {
    Origin,
    AuthSha1V4,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
}

impl SsrProtocol {
    /// Parse protocol plugin name from config string.
    ///
    /// Returns `None` only for names mihomo itself would reject with
    /// `protocol <name> not supported`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "origin" | "" => Some(SsrProtocol::Origin),
            "auth_sha1_v4" | "auth-sha1-v4" => Some(SsrProtocol::AuthSha1V4),
            "auth_aes128_md5" | "auth-aes128-md5" => Some(SsrProtocol::AuthAes128Md5),
            "auth_aes128_sha1" | "auth-aes128-sha1" => Some(SsrProtocol::AuthAes128Sha1),
            "auth_chain_a" | "auth-chain-a" => Some(SsrProtocol::AuthChainA),
            "auth_chain_b" | "auth-chain-b" => Some(SsrProtocol::AuthChainB),
            _ => None,
        }
    }

    /// Canonical mihomo name, used in error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            SsrProtocol::Origin => "origin",
            SsrProtocol::AuthSha1V4 => "auth_sha1_v4",
            SsrProtocol::AuthAes128Md5 => "auth_aes128_md5",
            SsrProtocol::AuthAes128Sha1 => "auth_aes128_sha1",
            SsrProtocol::AuthChainA => "auth_chain_a",
            SsrProtocol::AuthChainB => "auth_chain_b",
        }
    }

    /// Whether this protocol is actually implemented on the data path.
    ///
    /// Anything returning `false` here is rejected at config load rather than
    /// silently degraded to `origin`.
    pub fn is_implemented(&self) -> bool {
        matches!(self, SsrProtocol::Origin)
    }
}

/// SSR protocol plugin stream wrapper.
///
/// Only ever constructed for `origin` (all other protocols are rejected at
/// config load), so this is a transparent passthrough: reads and writes are
/// delegated to the inner stream without modification. `origin` matches
/// mihomo's `origin.Encode`/`origin.Decode`, which just copy bytes through.
pub struct SsrProtocolStream<T> {
    inner: T,
}

impl<T> SsrProtocolStream<T> {
    /// Create a new SSR protocol stream.
    ///
    /// Callers MUST have validated `protocol.is_implemented()` at config load;
    /// only `origin` reaches this point.
    pub fn new(inner: T, protocol: SsrProtocol, _param: &str) -> Self {
        debug_assert!(
            protocol.is_implemented(),
            "SsrProtocolStream constructed with unimplemented protocol {protocol:?}; \
             SsrOutbound::from_config must reject it at load"
        );
        Self { inner }
    }
}

impl<T: AsyncRead + Unpin + Send> AsyncRead for SsrProtocolStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // origin: direct passthrough.
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_from_name_recognizes_all_mihomo_names() {
        assert_eq!(SsrProtocol::from_name("origin"), Some(SsrProtocol::Origin));
        assert_eq!(SsrProtocol::from_name(""), Some(SsrProtocol::Origin));
        assert_eq!(
            SsrProtocol::from_name("auth_sha1_v4"),
            Some(SsrProtocol::AuthSha1V4)
        );
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
        // Unknown name → None (mihomo: "protocol <name> not supported").
        assert_eq!(SsrProtocol::from_name("unknown"), None);
    }

    #[test]
    fn only_origin_is_implemented() {
        assert!(SsrProtocol::Origin.is_implemented());
        assert!(!SsrProtocol::AuthSha1V4.is_implemented());
        assert!(!SsrProtocol::AuthAes128Md5.is_implemented());
        assert!(!SsrProtocol::AuthAes128Sha1.is_implemented());
        assert!(!SsrProtocol::AuthChainA.is_implemented());
        assert!(!SsrProtocol::AuthChainB.is_implemented());
    }
}
