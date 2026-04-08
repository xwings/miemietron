use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use http::Request;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional byte stream layered on top of an HTTP/2 connection.
///
/// Unlike gRPC, this does not add any extra framing -- data flows directly
/// as HTTP/2 DATA frames.
pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    read_buf: BytesMut,
    write_closed: bool,
}

impl H2Stream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::with_capacity(8192),
            write_closed: false,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain buffered data first.
        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        // 2. Poll the HTTP/2 receive stream.
        loop {
            match this.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    // Release flow-control capacity.
                    let _ = this.recv.flow_control().release_capacity(data.len());

                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        this.read_buf.extend_from_slice(&data[n..]);
                    }
                    return Poll::Ready(Ok(()));
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

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 write half closed",
            )));
        }

        // Wait for flow-control capacity.
        this.send.reserve_capacity(buf.len());
        match this.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(_))) => {}
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "H2 stream capacity exhausted",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }

        let data = Bytes::copy_from_slice(buf);
        this.send.send_data(data, false).map_err(io::Error::other)?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.write_closed = true;
            let _ = this.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

/// Establish an HTTP/2 stream over an existing async transport (typically TLS
/// with ALPN=h2).
///
/// Sends a `PUT` request to the given `path` (e.g. `"/"`), then returns an
/// `H2Stream` that implements `AsyncRead + AsyncWrite` for bidirectional
/// byte streaming.
pub async fn connect_h2<S>(stream: S, host: &str, path: &str) -> Result<H2Stream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo(stream);

    let (mut client, h2_conn) = h2::client::handshake(io).await?;

    // Spawn a task to drive the HTTP/2 connection state machine.
    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::debug!("h2 connection ended: {}", e);
        }
    });

    let request = Request::builder()
        .method("PUT")
        .uri(path)
        .header("host", host)
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build h2 request: {e}"))?;

    let (response_future, send_stream) = client.send_request(request, false)?;

    let response = response_future.await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("h2 server returned HTTP {status}");
    }

    let recv_stream = response.into_body();

    Ok(H2Stream::new(send_stream, recv_stream))
}

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
