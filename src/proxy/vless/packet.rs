//! Fixed-destination VLESS UDP over the configured stream transport.

use anyhow::{bail, Result};
use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::common::addr::Address;
use crate::proxy::OutboundPacketConn;

pub(super) struct VlessPacketConn<S> {
    reader: Mutex<PacketReader<ReadHalf<S>>>,
    writer: Mutex<WriteHalf<S>>,
    remote: Address,
}

struct PacketReader<R> {
    stream: R,
    header: [u8; 2],
    header_len: usize,
    payload: Vec<u8>,
    payload_len: usize,
}

impl<S: AsyncRead + AsyncWrite> VlessPacketConn<S> {
    pub(super) fn new(stream: S, remote: Address) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(PacketReader {
                stream: reader,
                header: [0; 2],
                header_len: 0,
                payload: Vec::new(),
                payload_len: 0,
            }),
            writer: Mutex::new(writer),
            remote,
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> OutboundPacketConn for VlessPacketConn<S> {
    async fn send_to(&self, data: &[u8], _target: &Address) -> Result<usize> {
        let length = u16::try_from(data.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "VLESS UDP packet too large")
        })?;
        let mut frame = Vec::with_capacity(2 + data.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(data);
        let mut writer = self.writer.lock().await;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(data.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let mut reader = self.reader.lock().await;
        let PacketReader {
            stream,
            header,
            header_len,
            payload,
            payload_len,
        } = &mut *reader;
        // Store partial progress in the connection: callers select between
        // receiving replies and forwarding new datagrams, cancelling this
        // future whenever another event wins.
        while *header_len < header.len() {
            let n = stream.read(&mut header[*header_len..]).await?;
            if n == 0 {
                bail!(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VLESS UDP length truncated"
                ));
            }
            *header_len += n;
        }
        let length = u16::from_be_bytes(*header) as usize;
        payload.resize(length, 0);
        while *payload_len < length {
            let n = stream.read(&mut payload[*payload_len..]).await?;
            if n == 0 {
                bail!(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VLESS UDP payload truncated"
                ));
            }
            *payload_len += n;
        }
        if buf.len() < length {
            // Retain the complete packet so retrying with a larger buffer
            // cannot desynchronize this stream or lose the next datagram.
            bail!(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS UDP receive buffer too small"
            ));
        }
        buf[..length].copy_from_slice(payload);
        *header_len = 0;
        *payload_len = 0;
        payload.clear();
        Ok((length, self.remote.clone()))
    }

    async fn close(&self) -> Result<()> {
        self.writer.lock().await.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::vless::header::{encode_request_with_flow, VlessStream, CMD_UDP};

    fn remote() -> Address {
        Address::ip("1.2.3.4:443".parse().unwrap())
    }

    #[tokio::test]
    async fn udp_wire_roundtrip_preserves_packet_boundaries_and_short_buffer_retry() {
        let (client, mut server) = tokio::io::duplex(256);
        let remote = remote();
        let header = encode_request_with_flow(&[0x11; 16], CMD_UDP, &remote, None);
        let packets = VlessPacketConn::new(VlessStream::new(client, header), remote.clone());
        assert_eq!(packets.send_to(b"hello", &remote).await.unwrap(), 5);
        assert_eq!(packets.send_to(b"next", &remote).await.unwrap(), 4);

        let mut wire = [0; 39];
        server.read_exact(&mut wire).await.unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(&[0x11; 16]);
        // Addon length, UDP command, port 443, IPv4 type and address.
        expected.extend_from_slice(&[0, 2, 1, 0xbb, 1, 1, 2, 3, 4]);
        expected.extend_from_slice(b"\x00\x05hello\x00\x04next");
        assert_eq!(wire.as_slice(), expected);

        let writer = tokio::spawn(async move {
            // Response addons and datagram lengths may all be fragmented by
            // TLS records or transport reads.
            for part in [
                &b"\x00"[..],
                &b"\x03xy"[..],
                &b"z\x00"[..],
                &b"\x05pong!\x00\x03two"[..],
            ] {
                server.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert!(packets.recv_from(&mut [0; 2]).await.is_err());
        let mut buf = [0; 32];
        let (n, from) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        assert_eq!(from, remote);
        let (n, _) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_receive_keeps_partial_length_and_payload() {
        let (client, mut server) = tokio::io::duplex(256);
        let packets = VlessPacketConn::new(VlessStream::new(client, Vec::new()), remote());
        server.write_all(b"\x00\x00\x00").await.unwrap();
        let mut buf = [0; 32];
        let mut receiving = Box::pin(packets.recv_from(&mut buf));
        assert!(futures_util::poll!(receiving.as_mut()).is_pending());
        drop(receiving);
        server.write_all(b"\x05po").await.unwrap();
        let mut receiving = Box::pin(packets.recv_from(&mut buf));
        assert!(futures_util::poll!(receiving.as_mut()).is_pending());
        drop(receiving);
        server.write_all(b"ng!\x00\x03two").await.unwrap();
        let (n, _) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        let (n, _) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");
    }

    #[tokio::test]
    async fn rejects_invalid_response_version_and_oversized_datagram() {
        let (client, mut server) = tokio::io::duplex(256);
        let packets = VlessPacketConn::new(VlessStream::new(client, Vec::new()), remote());
        assert!(packets.send_to(&vec![0; 65536], &remote()).await.is_err());
        server.write_all(b"\x01\x00\x00\x01x").await.unwrap();
        assert!(packets.recv_from(&mut [0; 32]).await.is_err());
    }
}
