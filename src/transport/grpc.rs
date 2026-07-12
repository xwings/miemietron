use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::Request;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// gRPC-over-HTTP/2 (gun) frame, per mihomo `transport/gun/gun.go`:
//   0x00 | grpcLen(u32 BE) | 0x0A | uvarint(dataLen) | dataLen bytes
// where grpcLen = 1 (the 0x0A tag) + varLen + dataLen. The `0x0A` is protobuf
// field #1, wire type 2 (length-delimited); the inner uvarint is that field's
// length. Omitting the tag+uvarint (as a naive gRPC-web framing would) is
// wire-incompatible with real mihomo/Xray gRPC peers.

/// Encode an unsigned LEB128 varint, appending to `out`. Mirrors Go's
/// `binary.PutUvarint`.
fn put_uvarint(out: &mut BytesMut, mut v: u64) {
    while v >= 0x80 {
        out.put_u8((v as u8) | 0x80);
        v >>= 7;
    }
    out.put_u8(v as u8);
}

/// Decode an unsigned LEB128 varint from `buf`. Returns `(value, bytes_read)`,
/// or `None` if the buffer does not yet contain a complete varint.
fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None; // overflow / malformed
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// A bidirectional byte stream layered on top of a gRPC (HTTP/2) connection.
///
/// On write, we wrap data in gun frames. On read, we accumulate raw HTTP/2
/// DATA into `incoming` and parse out complete gun frames, emitting only the
/// inner protobuf payload.
pub struct GrpcStream {
    /// HTTP/2 send stream -- used for writing data to the server.
    send: h2::SendStream<Bytes>,
    /// HTTP/2 receive stream -- used for reading data from the server.
    recv: h2::RecvStream,
    /// Raw HTTP/2 bytes not yet parsed into complete gun frames.
    incoming: BytesMut,
    /// Decoded payload bytes ready to hand to the caller.
    read_buf: BytesMut,
    /// True once we have sent an END_STREAM on the write half.
    write_closed: bool,
}

impl GrpcStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            incoming: BytesMut::with_capacity(8192),
            read_buf: BytesMut::with_capacity(8192),
            write_closed: false,
        }
    }

    /// Parse as many complete gun frames as possible out of `incoming` into
    /// `read_buf`. Returns true if at least one payload byte was produced.
    fn parse_incoming(&mut self) -> bool {
        parse_frames(&mut self.incoming, &mut self.read_buf)
    }
}

/// Parse complete gun frames from `incoming` into `read_buf`, consuming the
/// framed bytes. Returns true if at least one payload byte was produced.
/// Extracted as a free function so the framing logic is unit-testable without
/// live h2 handles.
fn parse_frames(incoming: &mut BytesMut, read_buf: &mut BytesMut) -> bool {
    let mut produced = false;
    loop {
        let buf = &incoming[..];
        if buf.len() < 5 {
            break; // need the 0x00 + u32 length header
        }
        let grpc_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + grpc_len {
            break; // full frame body not yet available
        }
        // body = [0x0A][uvarint dataLen][dataLen bytes]
        let body = &buf[5..5 + grpc_len];
        // body[0] is the 0x0A protobuf tag; skip it and read the length.
        if body.is_empty() || body[0] != 0x0A {
            // Malformed / unexpected framing — drop this frame to resync.
            incoming.advance(5 + grpc_len);
            continue;
        }
        if let Some((data_len, varlen)) = read_uvarint(&body[1..]) {
            let start = 1 + varlen;
            let end = start + data_len as usize;
            if end <= body.len() {
                read_buf.extend_from_slice(&body[start..end]);
                produced = produced || data_len > 0;
            }
        }
        incoming.advance(5 + grpc_len);
    }
    produced
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

                    this.incoming.extend_from_slice(&data);
                    this.parse_incoming();

                    if !this.read_buf.is_empty() {
                        let n = this.read_buf.len().min(buf.remaining());
                        buf.put_slice(&this.read_buf[..n]);
                        this.read_buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    // Only partial frame(s) so far; loop to poll more.
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

        // gun frame: 0x00 | grpcLen(u32 BE) | 0x0A | uvarint(dataLen) | payload
        // where grpcLen = 1 + varLen + dataLen (gun.go:132-137).
        let data_len = buf.len();
        let mut frame = BytesMut::with_capacity(6 + 5 + data_len);
        frame.put_u8(0x00); // compressed = false
                            // Reserve the 4-byte grpc length; fill after we know varLen.
        let grpc_len_pos = frame.len();
        frame.put_u32(0);
        frame.put_u8(0x0A); // protobuf field #1, wire type 2
        put_uvarint(&mut frame, data_len as u64);
        let var_len = frame.len() - grpc_len_pos - 4 - 1; // bytes used by uvarint
        let grpc_len = (1 + var_len + data_len) as u32;
        frame[grpc_len_pos..grpc_len_pos + 4].copy_from_slice(&grpc_len.to_be_bytes());
        frame.extend_from_slice(buf);

        // Wait for flow-control capacity for the full framed message.
        this.send.reserve_capacity(frame.len());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one gun frame exactly as `poll_write` does, for framing tests.
    fn encode_frame(payload: &[u8]) -> BytesMut {
        let data_len = payload.len();
        let mut frame = BytesMut::new();
        frame.put_u8(0x00);
        let pos = frame.len();
        frame.put_u32(0);
        frame.put_u8(0x0A);
        put_uvarint(&mut frame, data_len as u64);
        let var_len = frame.len() - pos - 4 - 1;
        let grpc_len = (1 + var_len + data_len) as u32;
        frame[pos..pos + 4].copy_from_slice(&grpc_len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn uvarint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, 1_000_000] {
            let mut b = BytesMut::new();
            put_uvarint(&mut b, v);
            let (decoded, n) = read_uvarint(&b).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, b.len());
        }
    }

    #[test]
    fn frame_matches_mihomo_layout() {
        // payload "hi" (len 2): 0x00 | 00000004 | 0x0A | 0x02 | "hi"
        let frame = encode_frame(b"hi");
        assert_eq!(
            &frame[..],
            &[0x00, 0x00, 0x00, 0x00, 0x04, 0x0A, 0x02, b'h', b'i']
        );
    }

    #[test]
    fn parse_frames_reassembles_two_messages() {
        let mut incoming = BytesMut::new();
        incoming.extend_from_slice(&encode_frame(b"hello"));
        incoming.extend_from_slice(&encode_frame(b"world"));
        let mut out = BytesMut::new();
        assert!(parse_frames(&mut incoming, &mut out));
        assert_eq!(&out[..], b"helloworld");
        assert!(incoming.is_empty());
    }

    #[test]
    fn parse_frames_waits_for_partial_frame() {
        let full = encode_frame(b"partial-data");
        // Feed all but the last byte: no complete frame yet.
        let mut incoming = BytesMut::from(&full[..full.len() - 1]);
        let mut out = BytesMut::new();
        assert!(!parse_frames(&mut incoming, &mut out));
        assert!(out.is_empty());
        // Deliver the final byte: the frame completes.
        incoming.extend_from_slice(&full[full.len() - 1..]);
        assert!(parse_frames(&mut incoming, &mut out));
        assert_eq!(&out[..], b"partial-data");
    }
}
