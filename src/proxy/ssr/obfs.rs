//! SSR obfuscation plugins.
//!
//! Obfuscation wraps the encrypted SSR stream to disguise traffic as other
//! protocols. The obfs layer sits *outside* the stream cipher — data is
//! first encrypted by the stream cipher, then wrapped by the obfs plugin.
//!
//! Supported plugins:
//! - `plain`: No obfuscation (passthrough).
//! - `http_simple`: Disguises the first packet as an HTTP request/response.
//! - `tls1.2_ticket_auth`: Placeholder (falls back to plain with a warning).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

/// Supported SSR obfuscation plugin types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrObfs {
    Plain,
    HttpSimple,
    Tls12TicketAuth,
}

impl SsrObfs {
    /// Parse obfs plugin name from config string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "plain" | "" => Some(SsrObfs::Plain),
            "http_simple" | "http-simple" => Some(SsrObfs::HttpSimple),
            "tls1.2_ticket_auth" | "tls12_ticket_auth" | "tls1.2-ticket-auth" => {
                Some(SsrObfs::Tls12TicketAuth)
            }
            _ => None,
        }
    }
}

/// SSR obfuscation stream wrapper.
///
/// For `plain`: complete passthrough — no transformation.
///
/// For `http_simple`:
/// - First write: prepend HTTP request headers.
/// - First read: skip HTTP response headers.
/// - After first exchange: passthrough.
///
/// For `tls1.2_ticket_auth`: currently falls back to plain with a warning.
pub struct SsrObfsStream<T> {
    inner: T,
    obfs: SsrObfs,
    param: String,
    write_state: ObfsWriteState,
    read_state: ObfsReadState,
}

enum ObfsWriteState {
    /// First write: need to prepend obfuscation header.
    NeedHeader,
    /// Flushing buffered header + data.
    Flushing { buf: Vec<u8>, pos: usize },
    /// Streaming passthrough.
    Streaming,
}

enum ObfsReadState {
    /// HTTP mode: need to read and skip the HTTP response header.
    HttpSkipHeader { header_buf: Vec<u8> },
    /// Buffered leftover data after stripping the header.
    Buffered { buf: Vec<u8>, pos: usize },
    /// Direct passthrough.
    Streaming,
}

impl<T: Unpin> Unpin for SsrObfsStream<T> {}

impl<T> SsrObfsStream<T> {
    /// Create a new SSR obfuscation stream.
    ///
    /// - `obfs`: the obfuscation type.
    /// - `param`: the obfs-param (e.g., hostname for http_simple).
    pub fn new(inner: T, obfs: SsrObfs, param: String) -> Self {
        let effective_obfs = match obfs {
            SsrObfs::Tls12TicketAuth => {
                warn!("ssr: tls1.2_ticket_auth obfs not yet implemented, falling back to plain");
                SsrObfs::Plain
            }
            other => other,
        };

        let (write_state, read_state) = match effective_obfs {
            SsrObfs::Plain => (ObfsWriteState::Streaming, ObfsReadState::Streaming),
            SsrObfs::HttpSimple => (
                ObfsWriteState::NeedHeader,
                ObfsReadState::HttpSkipHeader {
                    header_buf: Vec::new(),
                },
            ),
            SsrObfs::Tls12TicketAuth => {
                // Should not reach here due to fallback above, but just in case.
                (ObfsWriteState::Streaming, ObfsReadState::Streaming)
            }
        };

        Self {
            inner,
            obfs: effective_obfs,
            param,
            write_state,
            read_state,
        }
    }
}

/// Build a fake HTTP request header for http_simple obfs.
///
/// Format:
/// ```text
/// GET /{random_path} HTTP/1.1\r\n
/// Host: {param}\r\n
/// User-Agent: {random_ua}\r\n
/// Accept: text/html\r\n
/// Content-Length: {data_len}\r\n
/// Connection: keep-alive\r\n
/// \r\n
/// {data}
/// ```
fn build_http_simple_request(param: &str, payload: &[u8]) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Generate a short random hex path.
    let path_hex: String = (0..4)
        .map(|_| format!("{:02x}", rng.gen::<u8>()))
        .collect::<Vec<_>>()
        .join("");

    let host = if param.is_empty() {
        "www.bing.com"
    } else {
        param
    };

    let header = format!(
        "GET /{} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
         Accept: text/html,application/xhtml+xml,*/*\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        path_hex,
        host,
        payload.len()
    );

    let mut buf = Vec::with_capacity(header.len() + payload.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Find the position right after `\r\n\r\n` in a byte buffer.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for SsrObfsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ObfsReadState::Streaming => {
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }

                ObfsReadState::Buffered {
                    buf: ref buffered,
                    ref mut pos,
                } => {
                    let remaining = &buffered[*pos..];
                    if remaining.is_empty() {
                        this.read_state = ObfsReadState::Streaming;
                        continue;
                    }
                    let n = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..n]);
                    *pos += n;
                    return Poll::Ready(Ok(()));
                }

                ObfsReadState::HttpSkipHeader { ref mut header_buf } => {
                    // Read until we find \r\n\r\n (end of HTTP response header).
                    let mut tmp = [0u8; 512];
                    let mut read_buf = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "ssr obfs http_simple: EOF while reading response header",
                                )));
                            }
                            header_buf.extend_from_slice(read_buf.filled());

                            if let Some(end) = find_header_end(header_buf) {
                                let leftover = header_buf[end..].to_vec();
                                if leftover.is_empty() {
                                    this.read_state = ObfsReadState::Streaming;
                                } else {
                                    this.read_state = ObfsReadState::Buffered {
                                        buf: leftover,
                                        pos: 0,
                                    };
                                }
                                continue;
                            }
                            // Keep reading until we find the header end.
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for SsrObfsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Flush any pending buffered data first.
        while let ObfsWriteState::Flushing {
            ref buf,
            ref mut pos,
        } = this.write_state
        {
            if *pos < buf.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "ssr obfs: write zero",
                            )));
                        }
                        *pos += n;
                        if *pos < buf.len() {
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.write_state = ObfsWriteState::Streaming;
            break;
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match this.write_state {
            ObfsWriteState::NeedHeader => {
                let framed = match this.obfs {
                    SsrObfs::HttpSimple => build_http_simple_request(&this.param, data),
                    _ => data.to_vec(), // should not happen, but fallback
                };

                let data_len = data.len();
                match Pin::new(&mut this.inner).poll_write(cx, &framed) {
                    Poll::Ready(Ok(n)) => {
                        if n < framed.len() {
                            this.write_state = ObfsWriteState::Flushing {
                                buf: framed,
                                pos: n,
                            };
                        } else {
                            this.write_state = ObfsWriteState::Streaming;
                        }
                        Poll::Ready(Ok(data_len))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        this.write_state = ObfsWriteState::Flushing {
                            buf: framed,
                            pos: 0,
                        };
                        Poll::Ready(Ok(data_len))
                    }
                }
            }

            ObfsWriteState::Streaming => Pin::new(&mut this.inner).poll_write(cx, data),

            ObfsWriteState::Flushing { .. } => {
                unreachable!("ssr obfs: should have been flushed above");
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if let ObfsWriteState::Flushing {
            ref buf,
            ref mut pos,
        } = this.write_state
        {
            while *pos < buf.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "ssr obfs: write zero during flush",
                            )));
                        }
                        *pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        this.write_state = ObfsWriteState::Streaming;

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfs_from_name() {
        assert_eq!(SsrObfs::from_name("plain"), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_name(""), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_name("http_simple"), Some(SsrObfs::HttpSimple));
        assert_eq!(
            SsrObfs::from_name("tls1.2_ticket_auth"),
            Some(SsrObfs::Tls12TicketAuth)
        );
        assert_eq!(SsrObfs::from_name("unknown_obfs"), None);
    }

    #[test]
    fn http_simple_request_format() {
        let payload = b"encrypted data here";
        let req = build_http_simple_request("example.com", payload);
        let s = String::from_utf8_lossy(&req);

        assert!(s.starts_with("GET /"));
        assert!(s.contains("HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com"));
        assert!(s.contains(&format!("Content-Length: {}", payload.len())));
        assert!(s.contains("\r\n\r\n"));
        assert!(req.ends_with(b"encrypted data here"));
    }

    #[test]
    fn http_simple_default_host() {
        let req = build_http_simple_request("", b"data");
        let s = String::from_utf8_lossy(&req);
        assert!(s.contains("Host: www.bing.com"));
    }

    #[test]
    fn find_header_end_basic() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\ndata"), Some(19));
        assert_eq!(find_header_end(b"partial\r\n"), None);
        assert_eq!(find_header_end(b""), None);
    }
}
