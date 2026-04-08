//! Shadowsocks plugin implementations: simple-obfs, v2ray-plugin, shadow-tls.
//!
//! Each plugin wraps the raw TCP stream *before* the AEAD encryption layer,
//! providing obfuscation or transport encapsulation.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

// ---------------------------------------------------------------------------
// Plugin options helper
// ---------------------------------------------------------------------------

/// Parsed plugin options extracted from the config `plugin-opts` map.
#[derive(Debug, Clone, Default)]
pub struct PluginOpts {
    pub mode: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub tls: bool,
    pub password: Option<String>,
    pub version: Option<u32>,
}

impl PluginOpts {
    /// Parse plugin options from the serde_yaml value map.
    pub fn from_map(map: &HashMap<String, serde_yaml::Value>) -> Self {
        let get_str = |key: &str| -> Option<String> {
            map.get(key).and_then(|v| match v {
                serde_yaml::Value::String(s) => Some(s.clone()),
                _ => serde_yaml::to_string(v).ok().map(|s| s.trim().to_string()),
            })
        };
        let get_bool = |key: &str| -> bool {
            map.get(key)
                .map(|v| match v {
                    serde_yaml::Value::Bool(b) => *b,
                    serde_yaml::Value::String(s) => s == "true" || s == "1",
                    _ => false,
                })
                .unwrap_or(false)
        };
        let get_u32 = |key: &str| -> Option<u32> {
            map.get(key).and_then(|v| match v {
                serde_yaml::Value::Number(n) => n.as_u64().map(|n| n as u32),
                serde_yaml::Value::String(s) => s.parse().ok(),
                _ => None,
            })
        };

        Self {
            mode: get_str("mode"),
            host: get_str("host"),
            path: get_str("path"),
            tls: get_bool("tls"),
            password: get_str("password"),
            version: get_u32("version"),
        }
    }
}

// ===========================================================================
// simple-obfs (obfs-local): HTTP and TLS obfuscation modes
// ===========================================================================

/// Wraps a stream with simple-obfs HTTP or TLS obfuscation.
///
/// - **HTTP mode**: First write prepends a fake HTTP request header; first
///   read skips the HTTP response header.
/// - **TLS mode**: First write prepends a fake TLS ClientHello; subsequent
///   writes are framed as TLS Application Data records.  Reads strip the
///   TLS record framing.
pub struct ObfsStream<T> {
    inner: T,
    mode: ObfsMode,
    write_state: ObfsWriteState,
    read_state: ObfsReadState,
    host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObfsMode {
    Http,
    Tls,
}

enum ObfsWriteState {
    /// First write: need to prepend obfuscation header.
    NeedHeader,
    /// Flushing buffered header + data.
    Flushing { buf: Vec<u8>, pos: usize },
    /// Header sent, subsequent writes go through framing (TLS mode) or direct.
    Streaming,
}

enum ObfsReadState {
    /// HTTP mode: need to read and skip the HTTP response header (\r\n\r\n).
    HttpSkipHeader { header_buf: Vec<u8> },
    /// Buffered leftover data after stripping the header.
    Buffered { buf: Vec<u8>, pos: usize },
    /// Direct passthrough.
    Streaming,
    /// TLS mode: reading a TLS record header (5 bytes).
    TlsRecordHeader { hdr: Vec<u8> },
    /// TLS mode: reading record payload of known length.
    TlsRecordPayload { payload: Vec<u8>, remaining: usize },
}

// T: Unpin, and all other fields are Unpin, so ObfsStream is Unpin.
impl<T: Unpin> Unpin for ObfsStream<T> {}

impl<T> ObfsStream<T> {
    /// Create a new simple-obfs HTTP stream.
    pub fn new_http(inner: T, host: String) -> Self {
        Self {
            inner,
            mode: ObfsMode::Http,
            write_state: ObfsWriteState::NeedHeader,
            read_state: ObfsReadState::HttpSkipHeader {
                header_buf: Vec::new(),
            },
            host,
        }
    }

    /// Create a new simple-obfs TLS stream.
    pub fn new_tls(inner: T, host: String) -> Self {
        Self {
            inner,
            mode: ObfsMode::Tls,
            write_state: ObfsWriteState::NeedHeader,
            read_state: ObfsReadState::TlsRecordHeader { hdr: Vec::new() },
            host,
        }
    }
}

/// Build a fake HTTP request header for simple-obfs HTTP mode.
fn build_http_request(host: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/7.68.0\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Content-Length: {}\r\n\
         \r\n",
        host,
        payload.len()
    );
    let mut buf = Vec::with_capacity(header.len() + payload.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Build a fake TLS ClientHello for simple-obfs TLS mode.
fn build_tls_client_hello(host: &str) -> Vec<u8> {
    use rand::RngCore;

    let host_bytes = host.as_bytes();
    let sni_ext_len = 2 + 2 + 2 + 1 + 2 + host_bytes.len();

    let mut hello = Vec::with_capacity(256);

    // client_version: TLS 1.2
    hello.extend_from_slice(&[0x03, 0x03]);

    // random: 32 bytes
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    hello.extend_from_slice(&random);

    // session_id: 32 random bytes
    hello.push(32);
    let mut session_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_id);
    hello.extend_from_slice(&session_id);

    // cipher_suites
    let suites: &[u8] = &[0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x24, 0xc0, 0x23, 0x00, 0xff];
    hello.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(suites);

    // compression_methods: null
    hello.push(1);
    hello.push(0);

    // Extensions: SNI
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
    let sni_data_len = sni_ext_len - 4;
    extensions.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
    let sni_list_len = sni_data_len - 2;
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0x00); // host_name type
    extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);

    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Wrap in Handshake message (type 1 = ClientHello)
    let mut handshake = Vec::with_capacity(4 + hello.len());
    handshake.push(0x01);
    let hlen = hello.len();
    handshake.push(((hlen >> 16) & 0xFF) as u8);
    handshake.push(((hlen >> 8) & 0xFF) as u8);
    handshake.push((hlen & 0xFF) as u8);
    handshake.extend_from_slice(&hello);

    // Wrap in TLS record
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Wrap payload in a TLS Application Data record.
fn wrap_tls_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(0x17); // Application Data
    record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

/// Find the position right after `\r\n\r\n` in a byte buffer.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

// ---------------------------------------------------------------------------
// AsyncRead for ObfsStream (T: Unpin, so we use get_mut + Pin::new)
// ---------------------------------------------------------------------------

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for ObfsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ObfsReadState::Buffered {
                    buf: ref buffered_data,
                    ref mut pos,
                } => {
                    let remaining = &buffered_data[*pos..];
                    if remaining.is_empty() {
                        match this.mode {
                            ObfsMode::Http => this.read_state = ObfsReadState::Streaming,
                            ObfsMode::Tls => {
                                this.read_state =
                                    ObfsReadState::TlsRecordHeader { hdr: Vec::new() };
                            }
                        }
                        continue;
                    }
                    let n = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..n]);
                    *pos += n;
                    return Poll::Ready(Ok(()));
                }

                ObfsReadState::HttpSkipHeader { ref mut header_buf } => {
                    // Read chunks until we find \r\n\r\n.
                    let mut tmp = [0u8; 256];
                    let mut read_buf = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = read_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "obfs-http: EOF while reading response header",
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
                            // Keep reading.
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                ObfsReadState::Streaming => {
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }

                ObfsReadState::TlsRecordHeader { ref mut hdr } => {
                    while hdr.len() < 5 {
                        let remaining = 5 - hdr.len();
                        let mut tmp = vec![0u8; remaining];
                        let mut read_buf = ReadBuf::new(&mut tmp);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    if hdr.is_empty() {
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "obfs-tls: truncated record header",
                                    )));
                                }
                                hdr.extend_from_slice(read_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let payload_len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);

                    if payload_len == 0 {
                        this.read_state = ObfsReadState::TlsRecordHeader { hdr: Vec::new() };
                        continue;
                    }

                    this.read_state = ObfsReadState::TlsRecordPayload {
                        payload: Vec::with_capacity(payload_len),
                        remaining: payload_len,
                    };
                }

                ObfsReadState::TlsRecordPayload {
                    ref mut payload,
                    ref mut remaining,
                } => {
                    while *remaining > 0 {
                        let to_read = (*remaining).min(4096);
                        let mut tmp = vec![0u8; to_read];
                        let mut read_buf = ReadBuf::new(&mut tmp);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "obfs-tls: truncated record payload",
                                    )));
                                }
                                payload.extend_from_slice(read_buf.filled());
                                *remaining -= n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let data = std::mem::take(payload);
                    this.read_state = ObfsReadState::Buffered { buf: data, pos: 0 };
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncWrite for ObfsStream
// ---------------------------------------------------------------------------

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for ObfsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // First, flush any pending buffered data.
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
                                "obfs: write zero",
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
                let framed = match this.mode {
                    ObfsMode::Http => build_http_request(&this.host, data),
                    ObfsMode::Tls => {
                        let mut buf = build_tls_client_hello(&this.host);
                        buf.extend_from_slice(&wrap_tls_record(data));
                        buf
                    }
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
            ObfsWriteState::Streaming => match this.mode {
                ObfsMode::Http => Pin::new(&mut this.inner).poll_write(cx, data),
                ObfsMode::Tls => {
                    let record = wrap_tls_record(data);
                    let data_len = data.len();
                    match Pin::new(&mut this.inner).poll_write(cx, &record) {
                        Poll::Ready(Ok(n)) => {
                            if n < record.len() {
                                this.write_state = ObfsWriteState::Flushing {
                                    buf: record,
                                    pos: n,
                                };
                            }
                            Poll::Ready(Ok(data_len))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.write_state = ObfsWriteState::Flushing {
                                buf: record,
                                pos: 0,
                            };
                            Poll::Ready(Ok(data_len))
                        }
                    }
                }
            },
            ObfsWriteState::Flushing { .. } => {
                unreachable!("obfs: write state should have been flushed");
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
                                "obfs: write zero during flush",
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

// ===========================================================================
// v2ray-plugin (WebSocket mode)
// ===========================================================================

/// Connect through v2ray-plugin (WebSocket transport, optionally over TLS).
///
/// Returns a stream suitable for wrapping in `SsStream`.
pub async fn connect_v2ray_plugin<S>(
    stream: S,
    opts: &PluginOpts,
    server_host: &str,
) -> anyhow::Result<Box<dyn crate::proxy::ProxyStream>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = opts.host.as_deref().unwrap_or(server_host);
    let path = opts.path.as_deref().unwrap_or("/");

    if opts.tls {
        let tls_opts = crate::transport::tls::TlsOptions {
            sni: host.to_string(),
            skip_cert_verify: false,
            alpn: vec![],
            fingerprint: None,
        };
        let tls_stream = crate::transport::tls::wrap_tls(stream, &tls_opts).await?;

        let ws_opts = crate::transport::ws::WsOptions {
            host: host.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
        };
        let ws_stream = crate::transport::ws::wrap_ws(tls_stream, &ws_opts).await?;
        Ok(Box::new(ws_stream))
    } else {
        let ws_opts = crate::transport::ws::WsOptions {
            host: host.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
        };
        let ws_stream = crate::transport::ws::wrap_ws(stream, &ws_opts).await?;
        Ok(Box::new(ws_stream))
    }
}

// ===========================================================================
// shadow-tls v2 (stub + working TLS handshake)
// ===========================================================================

/// Connect through shadow-tls v2.
///
/// shadow-tls works by:
/// 1. Connecting to the shadow-tls server.
/// 2. Performing a real TLS handshake (proxied to a camouflage server).
/// 3. After the handshake, sending HMAC-authenticated SS data.
pub async fn connect_shadow_tls<S>(
    stream: S,
    opts: &PluginOpts,
    server_host: &str,
) -> anyhow::Result<ShadowTlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sni = opts.host.as_deref().unwrap_or(server_host);
    let password = opts.password.as_deref().unwrap_or("");

    debug!("shadow-tls v2: TLS handshake to SNI={}", sni);

    let tls_opts = crate::transport::tls::TlsOptions {
        sni: sni.to_string(),
        skip_cert_verify: true,
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        fingerprint: None,
    };
    let tls_stream = crate::transport::tls::wrap_tls(stream, &tls_opts).await?;

    Ok(ShadowTlsStream {
        inner: tls_stream,
        hmac_key: derive_shadow_tls_key(password.as_bytes()),
        hmac_sent: false,
    })
}

/// Derive the HMAC key for shadow-tls v2 from the password.
fn derive_shadow_tls_key(password: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(password);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

pin_project! {
    /// Stream wrapper for shadow-tls v2.
    ///
    /// After the TLS handshake, the first write is prefixed with an HMAC of
    /// the data (using the password-derived key).  Subsequent data passes
    /// through the TLS stream directly.
    pub struct ShadowTlsStream<T> {
        #[pin]
        inner: tokio_rustls::client::TlsStream<T>,
        hmac_key: [u8; 32],
        hmac_sent: bool,
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for ShadowTlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for ShadowTlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();

        if !*this.hmac_sent {
            use hmac::Mac;
            type HmacSha256 = hmac::Hmac<sha2::Sha256>;

            let mut mac = HmacSha256::new_from_slice(this.hmac_key)
                .map_err(|e| io::Error::other(format!("shadow-tls hmac init: {e}")))?;
            mac.update(data);
            let tag = mac.finalize().into_bytes();

            let mut buf = Vec::with_capacity(8 + data.len());
            buf.extend_from_slice(&tag[..8]);
            buf.extend_from_slice(data);

            let data_len = data.len();
            match this.inner.poll_write(cx, &buf) {
                Poll::Ready(Ok(n)) => {
                    if n >= 8 {
                        *this.hmac_sent = true;
                        let user_written = (n - 8).min(data_len);
                        Poll::Ready(Ok(user_written.max(1).min(data_len)))
                    } else {
                        Poll::Ready(Ok(0))
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            this.inner.poll_write(cx, data)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ===========================================================================
// shadow-tls v3 (strict mode with per-frame HMAC)
// ===========================================================================

/// Connect through shadow-tls v3 (strict mode).
///
/// V3 extends v2 by adding HMAC authentication to every TLS Application Data
/// frame, not just the first write. The HMAC covers the frame payload and uses
/// a per-connection counter as additional data to prevent replay.
pub async fn connect_shadow_tls_v3<S>(
    stream: S,
    opts: &PluginOpts,
    server_host: &str,
) -> anyhow::Result<ShadowTlsV3Stream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sni = opts.host.as_deref().unwrap_or(server_host);
    let password = opts.password.as_deref().unwrap_or("");

    debug!("shadow-tls v3: TLS handshake to SNI={}", sni);

    let tls_opts = crate::transport::tls::TlsOptions {
        sni: sni.to_string(),
        skip_cert_verify: true,
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        fingerprint: None,
    };
    let tls_stream = crate::transport::tls::wrap_tls(stream, &tls_opts).await?;

    Ok(ShadowTlsV3Stream {
        inner: tls_stream,
        hmac_key: derive_shadow_tls_key(password.as_bytes()),
        write_counter: 0,
    })
}

pin_project! {
    /// Stream wrapper for shadow-tls v3 (strict mode).
    ///
    /// Every write is prefixed with an 8-byte HMAC tag that covers the data
    /// and a monotonic counter. This prevents replay and ensures integrity
    /// of each frame.
    pub struct ShadowTlsV3Stream<T> {
        #[pin]
        inner: tokio_rustls::client::TlsStream<T>,
        hmac_key: [u8; 32],
        write_counter: u64,
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for ShadowTlsV3Stream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for ShadowTlsV3Stream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();

        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let mut mac = match HmacSha256::new_from_slice(this.hmac_key) {
            Ok(m) => m,
            Err(e) => return Poll::Ready(Err(io::Error::other(format!("hmac init: {e}")))),
        };

        // Include counter in HMAC to prevent replay
        mac.update(&this.write_counter.to_be_bytes());
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        *this.write_counter += 1;

        // Prefix data with 8-byte HMAC tag
        let mut buf = Vec::with_capacity(8 + data.len());
        buf.extend_from_slice(&tag[..8]);
        buf.extend_from_slice(data);

        let data_len = data.len();
        match this.inner.poll_write(cx, &buf) {
            Poll::Ready(Ok(n)) => {
                if n >= 8 {
                    let user_written = (n - 8).min(data_len);
                    Poll::Ready(Ok(user_written.max(1).min(data_len)))
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_opts_parsing() {
        let mut map = HashMap::new();
        map.insert(
            "mode".to_string(),
            serde_yaml::Value::String("http".to_string()),
        );
        map.insert(
            "host".to_string(),
            serde_yaml::Value::String("example.com".to_string()),
        );
        map.insert("tls".to_string(), serde_yaml::Value::Bool(true));
        map.insert(
            "password".to_string(),
            serde_yaml::Value::String("secret".to_string()),
        );
        map.insert(
            "version".to_string(),
            serde_yaml::Value::Number(serde_yaml::Number::from(2)),
        );

        let opts = PluginOpts::from_map(&map);
        assert_eq!(opts.mode.as_deref(), Some("http"));
        assert_eq!(opts.host.as_deref(), Some("example.com"));
        assert!(opts.tls);
        assert_eq!(opts.password.as_deref(), Some("secret"));
        assert_eq!(opts.version, Some(2));
    }

    #[test]
    fn http_request_header() {
        let payload = b"hello";
        let req = build_http_request("example.com", payload);
        let s = String::from_utf8_lossy(&req);
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com"));
        assert!(s.contains(&format!("Content-Length: {}", payload.len())));
        assert!(s.contains("\r\n\r\n"));
        assert!(req.ends_with(b"hello"));
    }

    #[test]
    fn tls_client_hello_structure() {
        let hello = build_tls_client_hello("example.com");
        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        let record_len = ((hello[3] as usize) << 8) | (hello[4] as usize);
        assert_eq!(hello.len(), 5 + record_len);
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn tls_application_data_record() {
        let payload = b"test data";
        let record = wrap_tls_record(payload);
        assert_eq!(record[0], 0x17);
        assert_eq!(&record[1..3], &[0x03, 0x03]);
        let len = ((record[3] as usize) << 8) | (record[4] as usize);
        assert_eq!(len, payload.len());
        assert_eq!(&record[5..], payload);
    }

    #[test]
    fn shadow_tls_key_derivation() {
        let key1 = derive_shadow_tls_key(b"password1");
        let key2 = derive_shadow_tls_key(b"password2");
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn find_header_end_basic() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\ndata"), Some(19));
        assert_eq!(find_header_end(b"partial\r\n"), None);
        assert_eq!(find_header_end(b""), None);
    }
}
