use pin_project_lite::pin_project;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::addr::Address;

/// VLESS protocol version.
const VLESS_VERSION: u8 = 0x00;

/// VLESS command types.
pub const CMD_TCP: u8 = 0x01;
#[allow(dead_code)]
pub const CMD_UDP: u8 = 0x02;

/// VLESS address types (SOCKS5 compatible).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// Parse a UUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into 16 raw bytes.
pub fn parse_uuid(s: &str) -> Result<[u8; 16], &'static str> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err("invalid UUID length");
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "invalid hex in UUID")?;
    }
    Ok(bytes)
}

/// Encode a SOCKS5-format address (used by both VLESS and Trojan).
pub fn encode_address(addr: &Address) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr {
        Address::Ip(sockaddr) => match sockaddr.ip() {
            IpAddr::V4(ipv4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&ipv4.octets());
                buf.extend_from_slice(&sockaddr.port().to_be_bytes());
            }
            IpAddr::V6(ipv6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&ipv6.octets());
                buf.extend_from_slice(&sockaddr.port().to_be_bytes());
            }
        },
        Address::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// Encode a VLESS request header (without flow addon).
///
/// Format:
/// ```text
/// [version: 1]  [uuid: 16]  [addon_len: 1]  [addons: variable]
/// [command: 1]  [address: variable]
/// ```
#[allow(dead_code)]
pub fn encode_request(uuid: &[u8; 16], cmd: u8, addr: &Address) -> Vec<u8> {
    encode_request_with_flow(uuid, cmd, addr, None)
}

/// Encode a VLESS request header with an optional flow addon.
///
/// When `flow` is `Some("xtls-rprx-vision")`, the addon is encoded as a
/// minimal protobuf message:
///
/// ```text
/// field 2 (string): tag = (2 << 3) | 2 = 0x12
///   length: len(flow)
///   value:  flow bytes
/// ```
///
/// The addon length byte encodes the total size of the protobuf payload.
pub fn encode_request_with_flow(
    uuid: &[u8; 16],
    cmd: u8,
    addr: &Address,
    flow: Option<&str>,
) -> Vec<u8> {
    let addr_bytes = encode_address(addr);

    // Build the addon bytes (protobuf-encoded flow string).
    let addon_bytes: Vec<u8> = match flow {
        Some(f) if !f.is_empty() => {
            // Protobuf: field 2, wire type 2 (length-delimited) = tag 0x12
            let flow_bytes = f.as_bytes();
            let mut addon = Vec::with_capacity(2 + flow_bytes.len());
            addon.push(0x12); // tag: field 2, wire type 2
            addon.push(flow_bytes.len() as u8); // varint length (flow < 128 bytes)
            addon.extend_from_slice(flow_bytes);
            addon
        }
        _ => Vec::new(),
    };

    let mut buf = Vec::with_capacity(1 + 16 + 1 + addon_bytes.len() + 1 + addr_bytes.len());

    // Version
    buf.push(VLESS_VERSION);
    // UUID
    buf.extend_from_slice(uuid);
    // Addon length
    buf.push(addon_bytes.len() as u8);
    // Addon payload
    buf.extend_from_slice(&addon_bytes);
    // Command
    buf.push(cmd);
    // Address
    buf.extend_from_slice(&addr_bytes);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn parse_uuid_valid() {
        let uuid = parse_uuid("12345678-1234-1234-1234-123456789abc").unwrap();
        assert_eq!(
            uuid,
            [
                0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
                0x9a, 0xbc
            ]
        );
    }

    #[test]
    fn parse_uuid_all_zeros() {
        let uuid = parse_uuid("00000000-0000-0000-0000-000000000000").unwrap();
        assert_eq!(uuid, [0u8; 16]);
    }

    #[test]
    fn parse_uuid_invalid_length() {
        assert!(parse_uuid("1234").is_err());
    }

    #[test]
    fn parse_uuid_invalid_hex() {
        assert!(parse_uuid("GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG").is_err());
    }

    #[test]
    fn encode_address_ipv4() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));
        let addr = Address::Ip(sock);
        let encoded = encode_address(&addr);
        assert_eq!(encoded[0], ATYP_IPV4);
        assert_eq!(&encoded[1..5], &[10, 0, 0, 1]);
        assert_eq!(&encoded[5..7], &443u16.to_be_bytes());
    }

    #[test]
    fn encode_address_ipv6() {
        let sock = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0));
        let addr = Address::Ip(sock);
        let encoded = encode_address(&addr);
        assert_eq!(encoded[0], ATYP_IPV6);
        assert_eq!(encoded.len(), 1 + 16 + 2);
        assert_eq!(&encoded[17..19], &80u16.to_be_bytes());
    }

    #[test]
    fn encode_address_domain() {
        let addr = Address::Domain("test.com".to_string(), 8443);
        let encoded = encode_address(&addr);
        assert_eq!(encoded[0], ATYP_DOMAIN);
        assert_eq!(encoded[1], 8); // "test.com".len()
        assert_eq!(&encoded[2..10], b"test.com");
        assert_eq!(&encoded[10..12], &8443u16.to_be_bytes());
    }

    #[test]
    fn encode_request_header() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        let addr = Address::Domain("example.com".to_string(), 443);
        let header = encode_request(&uuid, CMD_TCP, &addr);

        // Version
        assert_eq!(header[0], VLESS_VERSION);
        // UUID (bytes 1..17)
        assert_eq!(&header[1..17], &uuid);
        // Addon length
        assert_eq!(header[17], 0x00);
        // Command
        assert_eq!(header[18], CMD_TCP);
        // Address starts at byte 19
        assert_eq!(header[19], ATYP_DOMAIN);
    }

    #[test]
    fn encode_request_udp() {
        let uuid = [0u8; 16];
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let addr = Address::Ip(sock);
        let header = encode_request(&uuid, CMD_UDP, &addr);

        assert_eq!(header[18], CMD_UDP);
        assert_eq!(header[19], ATYP_IPV4);
    }

    #[test]
    fn encode_request_with_vision_flow() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        let addr = Address::Domain("example.com".to_string(), 443);
        let flow = "xtls-rprx-vision";
        let header = encode_request_with_flow(&uuid, CMD_TCP, &addr, Some(flow));

        // Version
        assert_eq!(header[0], VLESS_VERSION);
        // UUID (bytes 1..17)
        assert_eq!(&header[1..17], &uuid);
        // Addon length: 2 (tag + len) + 16 (flow string) = 18
        assert_eq!(header[17], 18);
        // Addon: protobuf tag for field 2, wire type 2
        assert_eq!(header[18], 0x12);
        // Addon: length of flow string
        assert_eq!(header[19], 16);
        // Addon: flow string
        assert_eq!(&header[20..36], flow.as_bytes());
        // Command (after addon)
        assert_eq!(header[36], CMD_TCP);
        // Address starts after command
        assert_eq!(header[37], ATYP_DOMAIN);
    }

    #[test]
    fn encode_request_no_flow_matches_original() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        let addr = Address::Domain("example.com".to_string(), 443);

        let h1 = encode_request(&uuid, CMD_TCP, &addr);
        let h2 = encode_request_with_flow(&uuid, CMD_TCP, &addr, None);
        let h3 = encode_request_with_flow(&uuid, CMD_TCP, &addr, Some(""));

        assert_eq!(h1, h2);
        assert_eq!(h1, h3);
    }
}

/// State machine for the VLESS stream wrapper.
enum ReadState {
    /// Waiting to read the VLESS response header.
    WaitingResponse,
    /// Response header has been consumed; pass through.
    Streaming,
}

enum WriteState {
    /// Need to prepend the VLESS request header to the first write.
    NeedHeader(Vec<u8>),
    /// Header has been sent; pass through.
    Streaming,
}

pin_project! {
    /// A stream wrapper that handles the VLESS handshake transparently.
    ///
    /// - On the first `write`, prepends the VLESS request header.
    /// - On the first `read`, consumes the VLESS response header.
    /// - After handshake, acts as a zero-overhead passthrough.
    pub struct VlessStream<T> {
        #[pin]
        inner: T,
        read_state: ReadState,
        write_state: WriteState,
        // Buffer for response header bytes being read.
        resp_buf: Vec<u8>,
    }
}

impl<T> VlessStream<T> {
    /// Create a new VLESS stream.
    ///
    /// `header` is the pre-encoded VLESS request header (from `encode_request`).
    pub fn new(inner: T, header: Vec<u8>) -> Self {
        Self {
            inner,
            read_state: ReadState::WaitingResponse,
            write_state: WriteState::NeedHeader(header),
            resp_buf: Vec::new(),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        match this.read_state {
            ReadState::Streaming => {
                // Passthrough
                this.inner.poll_read(cx, buf)
            }
            ReadState::WaitingResponse => {
                // We need to read at least 2 bytes: [version][addon_len]
                // Then `addon_len` more bytes for the addons.
                // Use a small temporary buffer to read bytes one-at-a-time
                // until we have enough to skip the response header.
                loop {
                    let needed = if this.resp_buf.len() < 2 {
                        // Still reading version + addon_len
                        2 - this.resp_buf.len()
                    } else {
                        // We know the addon length
                        let addon_len = this.resp_buf[1] as usize;
                        let total = 2 + addon_len;
                        if this.resp_buf.len() >= total {
                            // Response header fully consumed. Switch to streaming.
                            *this.read_state = ReadState::Streaming;
                            return this.inner.poll_read(cx, buf);
                        }
                        total - this.resp_buf.len()
                    };

                    // Read into a small stack buffer.
                    let mut tmp = vec![0u8; needed];
                    let mut tmp_buf = ReadBuf::new(&mut tmp);
                    match this.inner.as_mut().poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = tmp_buf.filled();
                            if filled.is_empty() {
                                // EOF before full response header
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "VLESS response header truncated",
                                )));
                            }
                            this.resp_buf.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessStream<T> {
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
                // Combine header + first payload into a single write for efficiency.
                let mut combined = std::mem::take(header);
                combined.extend_from_slice(buf);

                match this.inner.poll_write(cx, &combined) {
                    Poll::Ready(Ok(n)) => {
                        let header_len = combined.len() - buf.len();
                        if n < header_len {
                            // Partial header write: keep the unsent remainder.
                            *header = combined[n..header_len].to_vec();
                            // We haven't sent any user data yet, but we made progress.
                            // Return Pending-like by re-storing and trying again.
                            // Actually, report 0 user bytes written so caller retries.
                            Poll::Ready(Ok(0))
                        } else {
                            // Header fully sent. Switch to streaming.
                            *this.write_state = WriteState::Streaming;
                            let user_bytes = n - header_len;
                            Poll::Ready(Ok(user_bytes))
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        // Put header back so caller can retry
                        *header = combined[..combined.len() - buf.len()].to_vec();
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => {
                        // Put header back
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
