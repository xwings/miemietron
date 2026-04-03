use pin_project_lite::pin_project;
use sha2::{Digest, Sha224};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::addr::Address;
use crate::proxy::vless::header::encode_address;

/// Trojan command types.
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x03;

const CRLF: &[u8] = b"\r\n";

/// Compute the hex-encoded SHA-224 hash of a password.
/// Trojan protocol uses this as the authentication token.
pub fn hex_sha224(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Encode a Trojan request header (without payload).
///
/// Format:
/// ```text
/// [sha224_hex(password): 56 bytes ASCII]
/// [CRLF]
/// [command: 1 byte]
/// [address: SOCKS5 format]
/// [CRLF]
/// ```
pub fn encode_request(password_hash: &str, cmd: u8, addr: &Address) -> Vec<u8> {
    let addr_bytes = encode_address(addr);
    let mut buf = Vec::with_capacity(56 + 2 + 1 + addr_bytes.len() + 2);

    // Password hash (56 hex chars)
    buf.extend_from_slice(password_hash.as_bytes());
    // CRLF
    buf.extend_from_slice(CRLF);
    // Command
    buf.push(cmd);
    // Address
    buf.extend_from_slice(&addr_bytes);
    // CRLF
    buf.extend_from_slice(CRLF);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn sha224_known_value() {
        // SHA-224("password") is a known hash
        let hash = hex_sha224("password");
        assert_eq!(hash.len(), 56); // SHA-224 = 224 bits = 28 bytes = 56 hex chars
                                    // Verify against known SHA-224 hash of "password"
        assert_eq!(
            hash,
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn sha224_different_passwords() {
        let h1 = hex_sha224("alpha");
        let h2 = hex_sha224("bravo");
        assert_ne!(h1, h2);
        assert_eq!(h1.len(), 56);
        assert_eq!(h2.len(), 56);
    }

    #[test]
    fn sha224_empty_string() {
        let hash = hex_sha224("");
        assert_eq!(hash.len(), 56);
    }

    #[test]
    fn encode_request_header_structure() {
        let password_hash = hex_sha224("test-password");
        let addr = Address::Domain("example.com".to_string(), 443);
        let header = encode_request(&password_hash, CMD_TCP, &addr);

        // First 56 bytes: password hash
        assert_eq!(&header[..56], password_hash.as_bytes());
        // Next 2 bytes: CRLF
        assert_eq!(&header[56..58], b"\r\n");
        // Command byte
        assert_eq!(header[58], CMD_TCP);
        // Address starts at byte 59
        // (ATYP_DOMAIN from vless encode_address = 0x02)
        assert_eq!(header[59], 0x02);
        // Trailing CRLF
        let len = header.len();
        assert_eq!(&header[len - 2..], b"\r\n");
    }

    #[test]
    fn encode_request_with_ip() {
        let password_hash = hex_sha224("pw");
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let addr = Address::Ip(sock);
        let header = encode_request(&password_hash, CMD_UDP, &addr);

        assert_eq!(&header[..56], password_hash.as_bytes());
        assert_eq!(header[58], CMD_UDP);
        // IPv4 address type
        assert_eq!(header[59], 0x01);
    }
}

/// State machine for the write side.
enum WriteState {
    /// Need to prepend the Trojan request header to the first write.
    NeedHeader(Vec<u8>),
    /// Header has been sent; pass through.
    Streaming,
}

pin_project! {
    /// A stream wrapper that handles the Trojan handshake transparently.
    ///
    /// - On the first `write`, prepends the Trojan request header + first payload.
    /// - Reads pass through immediately (Trojan has no response header).
    /// - After the first write, acts as a zero-overhead passthrough.
    pub struct TrojanStream<T> {
        #[pin]
        inner: T,
        write_state: WriteState,
    }
}

impl<T> TrojanStream<T> {
    /// Create a new Trojan stream.
    ///
    /// `header` is the pre-encoded Trojan request header (from `encode_request`).
    pub fn new(inner: T, header: Vec<u8>) -> Self {
        Self {
            inner,
            write_state: WriteState::NeedHeader(header),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TrojanStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Trojan has no response header. Pure passthrough.
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TrojanStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();

        match this.write_state {
            WriteState::Streaming => {
                // Passthrough
                this.inner.poll_write(cx, buf)
            }
            WriteState::NeedHeader(ref mut header) => {
                // Combine header + first payload into a single write.
                // This is important: Trojan expects header + payload in one segment
                // to avoid detection by DPI.
                let mut combined = std::mem::take(header);
                combined.extend_from_slice(buf);

                match this.inner.poll_write(cx, &combined) {
                    Poll::Ready(Ok(n)) => {
                        let header_len = combined.len() - buf.len();
                        if n < header_len {
                            // Partial header write: keep unsent remainder.
                            *header = combined[n..header_len].to_vec();
                            Poll::Ready(Ok(0))
                        } else {
                            // Header fully sent.
                            *this.write_state = WriteState::Streaming;
                            let user_bytes = n - header_len;
                            Poll::Ready(Ok(user_bytes))
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        *header = combined[..combined.len() - buf.len()].to_vec();
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => {
                        *header = combined[..combined.len() - buf.len()].to_vec();
                        Poll::Pending
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
