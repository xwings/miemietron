//! sing UDP-over-TCP (UoT) client framing — `sing/common/uot` (protocol.go,
//! conn.go, lazy.go).
//!
//! A UDP association rides on any reliable stream opened to the magic
//! destination from [`request_destination`]. Version 2 starts with a request,
//! `[is_connect:u8][destination, SOCKS5 encoding]`; the legacy version 1 has
//! none. Every datagram is then `[length:u16 BE][payload]`, preceded — unless
//! the request asked for connect mode — by its own address in UoT's encoding:
//! family `0x00` IPv4, `0x01` IPv6 or `0x02` length-prefixed domain, then the
//! port.

use anyhow::{bail, Result};
use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::common::addr::{encode_socks5_into, Address};
use crate::proxy::OutboundPacketConn;

/// `uot.Version`: the first version with a request header.
pub const VERSION: u8 = 2;
/// `uot.LegacyVersion`: no request header; datagrams always carry an address.
#[allow(dead_code)] // For the Shadowsocks `udp-over-tcp-version` option.
pub const LEGACY_VERSION: u8 = 1;
const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

// `uot.AddrParser` address families.
const FAMILY_IPV4: u8 = 0x00;
const FAMILY_IPV6: u8 = 0x01;
const FAMILY_FQDN: u8 = 0x02;

/// `uot.RequestDestination`: where to open the stream so that the server
/// treats it as a UoT association of `version`.
pub fn request_destination(version: u8) -> Address {
    match version {
        0 | VERSION => Address::domain(MAGIC_ADDRESS, 0),
        _ => Address::domain(LEGACY_MAGIC_ADDRESS, 0),
    }
}

/// `uot.Request`.
#[derive(Debug, Clone)]
pub struct Request {
    /// Connect mode: every datagram goes to `destination` and none carries an
    /// address of its own.
    pub is_connect: bool,
    pub destination: Address,
}

/// sing `WriteSocksString`: a domain's length has to fit one byte.
fn check_fqdn(addr: &Address) -> io::Result<()> {
    match addr {
        Address::Domain(host, _) if host.len() > usize::from(u8::MAX) => {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "fqdn too long"))
        }
        _ => Ok(()),
    }
}

/// `uot.EncodeRequest`.
fn encode_request(request: &Request, buf: &mut Vec<u8>) -> io::Result<()> {
    check_fqdn(&request.destination)?;
    buf.push(u8::from(request.is_connect));
    encode_socks5_into(&request.destination, buf);
    Ok(())
}

/// `uot.AddrParser.WriteAddrPort`.
fn encode_addr(addr: &Address, buf: &mut Vec<u8>) -> io::Result<()> {
    check_fqdn(addr)?;
    match addr {
        Address::Ip(SocketAddr::V4(v4)) => {
            buf.push(FAMILY_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
        }
        Address::Ip(SocketAddr::V6(v6)) => {
            buf.push(FAMILY_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
        }
        Address::Domain(host, _) => {
            buf.push(FAMILY_FQDN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    Ok(())
}

/// `uot.AddrParser.ReadAddrPort` over an address [`PacketReader::read_frame`]
/// has buffered whole.
fn decode_addr(encoded: &[u8]) -> Address {
    let port = |at: usize| u16::from_be_bytes([encoded[at], encoded[at + 1]]);
    match encoded[0] {
        FAMILY_IPV4 => {
            let ip: [u8; 4] = encoded[1..5].try_into().unwrap();
            Address::ip(SocketAddr::new(Ipv4Addr::from(ip).into(), port(5)))
        }
        FAMILY_IPV6 => {
            let ip: [u8; 16] = encoded[1..17].try_into().unwrap();
            let ip = Ipv6Addr::from(ip);
            // sing reads IPv6 through `Socksaddr.Unwrap`: v4-mapped is IPv4.
            let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
            Address::ip(SocketAddr::new(ip, port(17)))
        }
        _ => {
            let len = usize::from(encoded[1]);
            if len == 0 {
                return Address::domain("", 0);
            }
            let host = String::from_utf8_lossy(&encoded[2..2 + len]);
            // sing `ParseSocksaddrHostPort`: an IP literal is an IP.
            match host.parse::<IpAddr>() {
                Ok(ip) => Address::ip(SocketAddr::new(ip, port(2 + len))),
                Err(_) => Address::domain(&host, port(2 + len)),
            }
        }
    }
}

/// A UDP association carried by a stream (`uot.Conn`).
pub struct UotPacketConn<S> {
    reader: Mutex<PacketReader<ReadHalf<S>>>,
    writer: Mutex<PacketWriter<WriteHalf<S>>>,
    request: Request,
}

struct PacketWriter<W> {
    stream: W,
    /// `uot.LazyClientConn`: the request header has yet to be sent, and
    /// leaves with the first datagram.
    request_pending: bool,
}

struct PacketReader<R> {
    stream: R,
    /// The frame being received and how much of it has arrived. Kept here
    /// rather than in a `recv_from` future, because callers cancel those.
    frame: Vec<u8>,
    filled: usize,
}

impl<S: AsyncRead + AsyncWrite> UotPacketConn<S> {
    /// `uot.NewLazyConn` — version 2: the request header is sent together
    /// with the first datagram.
    pub fn new_lazy(stream: S, request: Request) -> Self {
        Self::with_request_pending(stream, request, true)
    }

    /// `uot.NewConn`: no request header is written. The legacy version has
    /// none, and a version 2 caller may have sent it already.
    #[allow(dead_code)] // For the Shadowsocks `udp-over-tcp` option.
    pub fn new(stream: S, request: Request) -> Self {
        Self::with_request_pending(stream, request, false)
    }

    fn with_request_pending(stream: S, request: Request, request_pending: bool) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(PacketReader {
                stream: reader,
                frame: Vec::new(),
                filled: 0,
            }),
            writer: Mutex::new(PacketWriter {
                stream: writer,
                request_pending,
            }),
            request,
        }
    }
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    /// Read until `need` bytes of the current frame are buffered.
    async fn fill(&mut self, need: usize) -> io::Result<()> {
        if self.frame.len() < need {
            self.frame.resize(need, 0);
        }
        while self.filled < need {
            let n = self.stream.read(&mut self.frame[self.filled..need]).await?;
            if n == 0 {
                let reason = match self.filled {
                    0 => "UoT stream closed",
                    _ => "UoT frame truncated",
                };
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, reason));
            }
            self.filled += n;
        }
        Ok(())
    }

    /// Buffer one whole frame, resuming whatever a cancelled call left.
    /// Returns the length of its address and of its payload; the two-byte
    /// payload length sits between them.
    async fn read_frame(&mut self, is_connect: bool) -> io::Result<(usize, usize)> {
        let mut addr_len = 0;
        if !is_connect {
            self.fill(1).await?;
            addr_len = match self.frame[0] {
                FAMILY_IPV4 => 1 + 4 + 2,
                FAMILY_IPV6 => 1 + 16 + 2,
                FAMILY_FQDN => {
                    self.fill(2).await?;
                    match usize::from(self.frame[1]) {
                        // sing `ReadAddrPort`: an empty domain is no address,
                        // and no port follows it.
                        0 => 2,
                        len => 2 + len + 2,
                    }
                }
                family => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown address family: {family}"),
                    ))
                }
            };
        }
        self.fill(addr_len + 2).await?;
        let length = usize::from(u16::from_be_bytes([
            self.frame[addr_len],
            self.frame[addr_len + 1],
        ]));
        self.fill(addr_len + 2 + length).await?;
        Ok((addr_len, length))
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> OutboundPacketConn for UotPacketConn<S> {
    /// `uot.Conn.WriteTo`. In connect mode `target` is not used.
    async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize> {
        let length = u16::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UoT packet too large"))?;
        let mut writer = self.writer.lock().await;
        // The request, the address and the payload leave in one write, as
        // sing's vectorised write does: a framing transport underneath makes
        // each write a unit on the wire. The hint covers an IP address; a
        // long domain grows the buffer once.
        let mut frame = Vec::with_capacity(48 + data.len());
        if writer.request_pending {
            encode_request(&self.request, &mut frame)?;
        }
        if !self.request.is_connect {
            encode_addr(target, &mut frame)?;
        }
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(data);
        writer.stream.write_all(&frame).await?;
        writer.stream.flush().await?;
        writer.request_pending = false;
        Ok(data.len())
    }

    /// `uot.Conn.ReadFrom`. In connect mode the source is the destination of
    /// the request.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let mut reader = self.reader.lock().await;
        let (addr_len, length) = reader.read_frame(self.request.is_connect).await?;
        if buf.len() < length {
            // sing gives up on the stream here (`io.ErrShortBuffer`). Keeping
            // the datagram lets a retry with a larger buffer stay in step.
            bail!(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UoT read: short buffer"
            ));
        }
        let source = if self.request.is_connect {
            self.request.destination.clone()
        } else {
            decode_addr(&reader.frame[..addr_len])
        };
        let payload = addr_len + 2;
        buf[..length].copy_from_slice(&reader.frame[payload..payload + length]);
        reader.frame.clear();
        reader.filled = 0;
        Ok((length, source))
    }

    async fn close(&self) -> Result<()> {
        self.writer.lock().await.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn v4() -> Address {
        Address::ip("1.2.3.4:53".parse().unwrap())
    }

    fn request(is_connect: bool, destination: Address) -> Request {
        Request {
            is_connect,
            destination,
        }
    }

    async fn sent(server: &mut DuplexStream, len: usize) -> Vec<u8> {
        let mut wire = vec![0u8; len];
        server.read_exact(&mut wire).await.unwrap();
        wire
    }

    /// protocol.go RequestDestination: `case 0, Version` is the v2 name,
    /// everything else the legacy one.
    #[test]
    fn request_destination_is_the_magic_address_of_the_version() {
        for version in [0, VERSION] {
            assert_eq!(
                request_destination(version),
                Address::domain("sp.v2.udp-over-tcp.arpa", 0)
            );
        }
        for version in [LEGACY_VERSION, 3] {
            assert_eq!(
                request_destination(version),
                Address::domain("sp.udp-over-tcp.arpa", 0)
            );
        }
    }

    /// lazy.go + conn.go WriteTo, not connect mode: EncodeRequest
    /// (`IsConnect`, SocksaddrSerializer destination) rides ahead of the first
    /// datagram only; each datagram is AddrParser address, u16 length,
    /// payload.
    #[tokio::test]
    async fn lazy_v2_sends_the_request_with_the_first_datagram() {
        let (client, mut server) = tokio::io::duplex(1024);
        let packets = UotPacketConn::new_lazy(client, request(false, v4()));

        assert_eq!(packets.send_to(b"hello", &v4()).await.unwrap(), 5);
        let mut expected = vec![0x00]; // IsConnect = false
        expected.extend_from_slice(&[0x01, 1, 2, 3, 4, 0x00, 0x35]); // SOCKS5 IPv4, port 53
        expected.extend_from_slice(&[0x00, 1, 2, 3, 4, 0x00, 0x35]); // UoT IPv4, port 53
        expected.extend_from_slice(b"\x00\x05hello");
        assert_eq!(sent(&mut server, expected.len()).await, expected);

        let v6 = Address::ip("[2001:db8::1]:443".parse().unwrap());
        packets.send_to(b"next", &v6).await.unwrap();
        let mut expected = vec![0x01, 0x20, 0x01, 0x0d, 0xb8]; // UoT IPv6
        expected.extend_from_slice(&[0; 11]);
        expected.extend_from_slice(&[0x01, 0x01, 0xbb]); // ..::1, port 443
        expected.extend_from_slice(b"\x00\x04next");
        assert_eq!(sent(&mut server, expected.len()).await, expected);

        let domain = Address::domain("example.com", 80);
        packets.send_to(b"hi", &domain).await.unwrap();
        let expected = b"\x02\x0bexample.com\x00\x50\x00\x02hi"; // UoT domain
        assert_eq!(sent(&mut server, expected.len()).await, expected);
    }

    /// Connect mode: `IsConnect = true` in the request, then bare
    /// length-prefixed datagrams in both directions (conn.go `if !c.isConnect`).
    #[tokio::test]
    async fn connect_mode_frames_carry_no_address() {
        let (client, mut server) = tokio::io::duplex(1024);
        let destination = Address::domain("example.com", 443);
        let packets = UotPacketConn::new_lazy(client, request(true, destination.clone()));

        packets.send_to(b"hello", &v4()).await.unwrap();
        packets.send_to(b"next", &v4()).await.unwrap();
        // IsConnect, SOCKS5 domain destination, then the two datagrams.
        let expected = b"\x01\x03\x0bexample.com\x01\xbb\x00\x05hello\x00\x04next";
        assert_eq!(sent(&mut server, expected.len()).await, expected);

        server.write_all(b"\x00\x04pong").await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from, destination);
    }

    /// client.go DialConn `case LegacyVersion`: NewConn with nothing written
    /// first, so the stream starts with a datagram.
    #[tokio::test]
    async fn legacy_v1_has_no_request_header() {
        let (client, mut server) = tokio::io::duplex(1024);
        let packets = UotPacketConn::new(client, request(false, v4()));
        packets.send_to(b"hello", &v4()).await.unwrap();
        let expected = b"\x00\x01\x02\x03\x04\x00\x35\x00\x05hello";
        assert_eq!(sent(&mut server, expected.len()).await, expected);
    }

    /// conn.go ReadFrom over every AddrParser family, with the frames cut at
    /// arbitrary points the way a transport delivers them.
    #[tokio::test]
    async fn receive_parses_every_address_family_across_fragmented_reads() {
        let (client, mut server) = tokio::io::duplex(1024);
        let packets = UotPacketConn::new_lazy(client, request(false, v4()));
        let writer = tokio::spawn(async move {
            for part in [
                &b"\x00\x09\x09"[..],
                &b"\x09\x09\x00"[..],
                &b"\x35\x00\x04ipv4"[..],
                // 2001:db8::1 port 443
                &b"\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"[..],
                &b"\x00\x00\x00\x01\x01\xbb\x00\x04ipv6"[..],
                // ::ffff:10.0.0.1 port 80, which sing unwraps to IPv4
                &b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0a\x00\x00\x01"[..],
                &b"\x00\x50\x00\x06mapped"[..],
                &b"\x02\x0bexam"[..],
                &b"ple.com\x00\x50\x00"[..],
                &b"\x06domain\x00\x01\x02\x03\x04\x00\x35\x00\x00"[..],
            ] {
                server.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
            server
        });
        let mut buf = [0u8; 32];
        for (payload, source) in [
            (&b"ipv4"[..], Address::ip("9.9.9.9:53".parse().unwrap())),
            (b"ipv6", Address::ip("[2001:db8::1]:443".parse().unwrap())),
            (b"mapped", Address::ip("10.0.0.1:80".parse().unwrap())),
            (b"domain", Address::domain("example.com", 80)),
            (b"", v4()),
        ] {
            let (n, from) = packets.recv_from(&mut buf).await.unwrap();
            assert_eq!((&buf[..n], from), (payload, source));
        }
        drop(writer.await.unwrap());
        // The stream ends between frames.
        let error = packets.recv_from(&mut buf).await.unwrap_err();
        assert_eq!(error.to_string(), "UoT stream closed");
    }

    /// The `OutboundPacketConn` contract: the relay drops a `recv_from` that
    /// lost a `select!`, and the next call must pick the frame up where that
    /// one stopped.
    #[tokio::test]
    async fn cancelled_receive_keeps_the_partial_frame() {
        let (client, mut server) = tokio::io::duplex(1024);
        let packets = UotPacketConn::new_lazy(client, request(false, v4()));
        let mut buf = [0u8; 32];
        for part in [
            &b"\x02"[..],        // family
            &b"\x0bexample"[..], // domain length, part of the domain
            &b".com\x00"[..],    // rest of it, half the port
            &b"\x50\x00"[..],    // port, half the length
            &b"\x05po"[..],      // length, part of the payload
        ] {
            server.write_all(part).await.unwrap();
            let mut receiving = Box::pin(packets.recv_from(&mut buf));
            assert!(futures_util::poll!(receiving.as_mut()).is_pending());
        }
        server
            .write_all(b"ng!\x00\x01\x02\x03\x04\x00\x35\x00\x03two")
            .await
            .unwrap();
        let (n, from) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        assert_eq!(from, Address::domain("example.com", 80));
        let (n, from) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");
        assert_eq!(from, v4());
    }

    #[tokio::test]
    async fn short_buffer_keeps_the_datagram_and_bad_input_is_rejected() {
        let (client, mut server) = tokio::io::duplex(1024);
        let packets = UotPacketConn::new_lazy(client, request(false, v4()));
        server
            .write_all(b"\x00\x01\x02\x03\x04\x00\x35\x00\x05hello")
            .await
            .unwrap();
        let error = packets.recv_from(&mut [0u8; 2]).await.unwrap_err();
        assert_eq!(error.to_string(), "UoT read: short buffer");
        let mut buf = [0u8; 32];
        let (n, _) = packets.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // A datagram longer than the length field, a domain longer than its
        // length byte (sing: "fqdn too long") — and neither wrote anything.
        assert!(packets.send_to(&vec![0u8; 65536], &v4()).await.is_err());
        let long = Address::domain(&"a".repeat(256), 53);
        let error = packets.send_to(b"x", &long).await.unwrap_err();
        assert_eq!(error.to_string(), "fqdn too long");
        packets.send_to(b"ok", &v4()).await.unwrap();
        assert_eq!(sent(&mut server, 1).await, [0x00], "request still leads");

        // serializer.go ReadAddress: a family AddrParser does not know.
        server.write_all(b"\x03\x01\x02").await.unwrap();
        let error = packets.recv_from(&mut buf).await.unwrap_err();
        assert_eq!(error.to_string(), "unknown address family: 3");
        // Cut off inside a frame.
        let (client, mut server) = tokio::io::duplex(1024);
        let packets = UotPacketConn::new_lazy(client, request(true, v4()));
        server.write_all(b"\x00\x05he").await.unwrap();
        drop(server);
        let error = packets.recv_from(&mut buf).await.unwrap_err();
        assert_eq!(error.to_string(), "UoT frame truncated");
    }
}
