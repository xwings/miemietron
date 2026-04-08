use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::Request;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// gRPC frame header size: 1 byte compressed flag + 4 bytes payload length.
const GRPC_HEADER_LEN: usize = 5;

// ---------------------------------------------------------------------------
// GrpcStream: AsyncRead + AsyncWrite over gRPC/HTTP2
// ---------------------------------------------------------------------------

/// A bidirectional byte stream layered on top of a gRPC (HTTP/2) connection.
///
/// gRPC framing: each message is prefixed with a 5-byte header:
///   - 1 byte: compressed flag (always 0 for us)
///   - 4 bytes: big-endian payload length
///
/// On write, we wrap data in gRPC frames.
/// On read, we strip the gRPC frame headers.
pub struct GrpcStream {
    /// HTTP/2 send stream -- used for writing data to the server.
    send: h2::SendStream<Bytes>,
    /// HTTP/2 receive stream -- used for reading data from the server.
    recv: h2::RecvStream,
    /// Buffered incoming data (after stripping gRPC frame headers).
    read_buf: BytesMut,
    /// True once we have sent an END_STREAM on the write half.
    write_closed: bool,
    /// State machine for reading gRPC frames (we may get partial headers).
    frame_state: FrameReadState,
}

/// State for incrementally reading gRPC frame headers from the HTTP/2 stream.
#[derive(Debug)]
enum FrameReadState {
    /// Waiting for / accumulating the 5-byte gRPC header.
    Header {
        collected: [u8; GRPC_HEADER_LEN],
        len: usize,
    },
    /// Reading `remaining` bytes of payload for the current frame.
    Payload { remaining: usize },
}

impl GrpcStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::with_capacity(8192),
            write_closed: false,
            frame_state: FrameReadState::Header {
                collected: [0u8; GRPC_HEADER_LEN],
                len: 0,
            },
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain any buffered payload data first.
        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        // 2. Poll the HTTP/2 receive stream for more data.
        loop {
            match this.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    // Release flow-control capacity so the sender can keep sending.
                    let _ = this.recv.flow_control().release_capacity(data.len());

                    // Feed data through the gRPC frame state machine.
                    let mut cursor = &data[..];
                    while !cursor.is_empty() {
                        match &mut this.frame_state {
                            FrameReadState::Header { collected, len } => {
                                let need = GRPC_HEADER_LEN - *len;
                                let take = need.min(cursor.len());
                                collected[*len..*len + take].copy_from_slice(&cursor[..take]);
                                cursor = &cursor[take..];
                                *len += take;

                                if *len == GRPC_HEADER_LEN {
                                    // Parse the 4-byte big-endian length (skip byte 0 = compressed flag).
                                    let payload_len = u32::from_be_bytes([
                                        collected[1],
                                        collected[2],
                                        collected[3],
                                        collected[4],
                                    ])
                                        as usize;
                                    this.frame_state = FrameReadState::Payload {
                                        remaining: payload_len,
                                    };
                                }
                            }
                            FrameReadState::Payload { remaining } => {
                                let take = (*remaining).min(cursor.len());
                                this.read_buf.extend_from_slice(&cursor[..take]);
                                cursor = &cursor[take..];
                                *remaining -= take;

                                if *remaining == 0 {
                                    this.frame_state = FrameReadState::Header {
                                        collected: [0u8; GRPC_HEADER_LEN],
                                        len: 0,
                                    };
                                }
                            }
                        }
                    }

                    // Now drain whatever we accumulated.
                    if !this.read_buf.is_empty() {
                        let n = this.read_buf.len().min(buf.remaining());
                        buf.put_slice(&this.read_buf[..n]);
                        this.read_buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    // All data was header bytes; loop to poll more.
                    continue;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(None) => {
                    // Stream ended (EOF).
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC write half closed",
            )));
        }

        // Wait for flow-control capacity.
        this.send.reserve_capacity(GRPC_HEADER_LEN + buf.len());
        match this.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(_))) => {}
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "gRPC stream capacity exhausted",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Build the gRPC frame: [0x00] [4-byte big-endian length] [payload]
        let mut frame = BytesMut::with_capacity(GRPC_HEADER_LEN + buf.len());
        frame.put_u8(0); // compressed = false
        frame.put_u32(buf.len() as u32);
        frame.extend_from_slice(buf);

        this.send
            .send_data(frame.freeze(), false)
            .map_err(io::Error::other)?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 flushes automatically; nothing to do here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.write_closed = true;
            // Send an empty DATA frame with END_STREAM.
            let _ = this.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// connect_grpc -- establish a gRPC stream over an existing transport
// ---------------------------------------------------------------------------

/// Establish a gRPC stream over an existing async transport (typically TLS).
///
/// This performs the HTTP/2 handshake, sends a POST request to
/// `/{service_name}/Tun`, and returns a `GrpcStream` that implements
/// `AsyncRead + AsyncWrite`.
///
/// The caller is responsible for TLS (with ALPN=h2) before calling this.
pub async fn connect_grpc<S>(stream: S, service_name: &str, host: &str) -> Result<GrpcStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo(stream);

    let (mut client, h2_conn) = h2::client::handshake(io).await?;

    // Spawn a task to drive the HTTP/2 connection state machine.
    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::debug!("gRPC h2 connection ended: {}", e);
        }
    });

    let path = format!("/{service_name}/Tun");
    let request = Request::builder()
        .method("POST")
        .uri(&path)
        .header("host", host)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "grpc-go/1.64.0")
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build gRPC request: {e}"))?;

    let (response_future, send_stream) = client.send_request(request, false)?;

    // Wait for the response headers.
    let response = response_future.await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("gRPC server returned HTTP {status}");
    }

    let recv_stream = response.into_body();

    Ok(GrpcStream::new(send_stream, recv_stream))
}

// ---------------------------------------------------------------------------
// TokioIo adapter: bridge tokio::io traits to h2's I/O requirements
// ---------------------------------------------------------------------------

/// Adapter that implements `h2`'s required I/O traits (tokio AsyncRead/AsyncWrite)
/// by delegating to the inner stream. This is needed because `h2::client::handshake`
/// requires `tokio::io::AsyncRead + tokio::io::AsyncWrite` directly, and our
/// generic `S` already satisfies that -- but the compiler sometimes needs an
/// explicit bridge when trait bounds differ between crate versions.
struct TokioIo<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for TokioIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TokioIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
