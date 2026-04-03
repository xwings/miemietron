use anyhow::Result;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::sink::Sink;
use futures_util::stream::Stream;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::HeaderName;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

/// Maximum payload size for WebSocket early data sent in the
/// `Sec-WebSocket-Protocol` header during the upgrade request.
/// mihomo / clash.meta use 2048 bytes by default.
const DEFAULT_MAX_EARLY_DATA: usize = 2048;

// ---------------------------------------------------------------------------
// WsOptions / wrap_ws -- compatibility API used by proxy adapters
// ---------------------------------------------------------------------------

/// Options for WebSocket connections.
#[derive(Debug, Clone, Default)]
pub struct WsOptions {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// Convenience function: wrap an existing async stream with a WebSocket
/// client upgrade using `WsOptions`.
pub async fn wrap_ws<S>(stream: S, opts: &WsOptions) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let headers: HashMap<String, String> = opts.headers.iter().cloned().collect();
    let hdr_ref = if headers.is_empty() {
        None
    } else {
        Some(&headers)
    };
    connect(stream, &opts.path, &opts.host, hdr_ref).await
}

// ---------------------------------------------------------------------------
// Primary connect functions
// ---------------------------------------------------------------------------

/// Connect over WebSocket, performing the HTTP upgrade on `stream`.
///
/// * `stream`  -- Underlying transport (TCP or TLS stream).
/// * `path`    -- WebSocket path, e.g. `"/ws"`.
/// * `host`    -- Value for the Host header.
/// * `headers` -- Optional additional HTTP headers.
///
/// Returns a `WsStream` that implements `AsyncRead + AsyncWrite`.
pub async fn connect<S>(
    stream: S,
    path: &str,
    host: &str,
    headers: Option<&HashMap<String, String>>,
) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    connect_with_early_data(stream, path, host, headers, None).await
}

/// Connect over WebSocket with optional early-data payload.
///
/// When `early_data` is `Some`, the first chunk of proxy payload is base64-
/// encoded and sent in the `Sec-WebSocket-Protocol` header during the HTTP
/// upgrade.  This mirrors the behaviour of clash.meta / mihomo's
/// `max-early-data` option and avoids a full round-trip for the first packet.
///
/// The early data must not exceed `DEFAULT_MAX_EARLY_DATA` bytes; if it does,
/// it is silently truncated and the remainder will be the first `WsStream`
/// write.
pub async fn connect_with_early_data<S>(
    stream: S,
    path: &str,
    host: &str,
    headers: Option<&HashMap<String, String>>,
    early_data: Option<&[u8]>,
) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build the upgrade request.
    let url = format!("ws://{}{}", host, path);
    let mut request = url.into_client_request()?;

    {
        let hdrs = request.headers_mut();

        // Override Host in case the URL-derived one differs (common behind CDN).
        hdrs.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_str(host)
                .map_err(|e| anyhow::anyhow!("invalid host header: {}", e))?,
        );

        // Caller-supplied headers.
        if let Some(extra) = headers {
            for (key, value) in extra {
                if let (Ok(name), Ok(val)) =
                    (key.parse::<HeaderName>(), HeaderValue::from_str(value))
                {
                    hdrs.insert(name, val);
                }
            }
        }

        // Early data: encode into Sec-WebSocket-Protocol.
        if let Some(data) = early_data {
            let to_send = if data.len() > DEFAULT_MAX_EARLY_DATA {
                &data[..DEFAULT_MAX_EARLY_DATA]
            } else {
                data
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(to_send);
            hdrs.insert(
                HeaderName::from_static("sec-websocket-protocol"),
                HeaderValue::from_str(&encoded)
                    .map_err(|e| anyhow::anyhow!("early-data header encoding failed: {}", e))?,
            );
        }
    }

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream).await?;

    Ok(WsStream::new(ws_stream))
}

// ---------------------------------------------------------------------------
// WsStream: AsyncRead + AsyncWrite adapter over WebSocket binary frames
// ---------------------------------------------------------------------------

/// A bidirectional byte stream layered on top of a WebSocket connection.
///
/// Reads extract data from `Binary` (and `Text`) frames. Writes produce
/// `Binary` frames.  Control frames (Ping/Pong/Close) are handled
/// transparently.
pub struct WsStream<S> {
    sink: SplitSink<WebSocketStream<S>, Message>,
    stream: SplitStream<WebSocketStream<S>>,
    /// Leftover bytes from a partially-consumed incoming frame.
    read_buf: Bytes,
    /// Current read offset into `read_buf`.
    read_pos: usize,
    /// True once we have initiated the close handshake.
    write_closed: bool,
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(ws: WebSocketStream<S>) -> Self {
        let (sink, stream) = ws.split();
        Self {
            sink,
            stream,
            read_buf: Bytes::new(),
            read_pos: 0,
            write_closed: false,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain any leftover bytes from the previous frame.
        if this.read_pos < this.read_buf.len() {
            let remaining = &this.read_buf[this.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.read_pos += n;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf = Bytes::new();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 2. Poll for the next WebSocket message.
        loop {
            return match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    let data: Bytes = match msg {
                        Message::Binary(d) => d,
                        Message::Text(t) => Bytes::from(Vec::from(t.as_bytes())),
                        Message::Close(_) => {
                            // Graceful EOF.
                            return Poll::Ready(Ok(()));
                        }
                        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                            // Skip control frames and poll again.
                            continue;
                        }
                    };

                    if data.is_empty() {
                        return Poll::Ready(Ok(()));
                    }

                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        this.read_buf = data;
                        this.read_pos = n;
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(None) => {
                    // Underlying stream ended => EOF.
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket write half closed",
            )));
        }

        // Ensure the sink is ready to accept a message.
        match Pin::new(&mut this.sink).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Pending => return Poll::Pending,
        }

        let msg = Message::Binary(Bytes::copy_from_slice(buf));
        match Pin::new(&mut this.sink).start_send(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.sink)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_closed = true;
        Pin::new(&mut this.sink)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}
