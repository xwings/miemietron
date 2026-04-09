/// UDP relay for Shadowsocks — AEAD encryption/decryption per packet.
///
/// SS UDP packet format (legacy AEAD):
///   Send: [salt][encrypted(addr_header + data) + tag]
///   Recv: [salt][encrypted(addr_header + data) + tag]
///
/// Each UDP packet is independently encrypted with a fresh random salt.
/// There is no nonce counter — each packet uses nonce = 0.
use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tracing::debug;

use super::aead::{
    decrypt_in_place_standalone, encode_address_into, encrypt_in_place_standalone, AeadCipher,
};
use crate::common::addr::Address;

/// AEAD tag size for all supported ciphers (16 bytes).
const TAG_LEN: usize = 16;

/// Nonce for UDP packets — always zero (each packet has a fresh salt/key).
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Shadowsocks UDP socket — wraps a `UdpSocket` and encrypts/decrypts with AEAD.
pub struct SsUdpSocket {
    inner: UdpSocket,
    cipher: AeadCipher,
    master_key: Vec<u8>,
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
}

impl SsUdpSocket {
    /// Create a new `SsUdpSocket` that communicates with the given SS server.
    ///
    /// Binds a local UDP socket, sets SO_MARK for TUN bypass, and connects
    /// to the SS server.
    pub async fn new(
        server_addr: SocketAddr,
        cipher: AeadCipher,
        master_key: Vec<u8>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // mihomo compat: no hardcoded SO_MARK on outbound sockets.
        // GID 65534 (set by OpenClash via procd) handles firewall bypass.
        // SO_MARK is only applied when routing-mark is explicitly configured.

        socket.connect(server_addr).await?;

        Ok(Self {
            inner: socket,
            cipher,
            master_key,
            recv_buf: tokio::sync::Mutex::new(vec![0u8; 65535]),
        })
    }

    /// Send `data` to `target` through the SS server, encrypted with AEAD.
    ///
    /// Constructs the packet: `[salt][encrypted(addr_header + data) + tag]`
    pub async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize> {
        let salt_len = self.cipher.salt_len();

        // Single allocation: [salt | addr_header + data (plaintext, encrypted in-place + tag)]
        let mut plaintext = Vec::with_capacity(data.len() + 32); // 32 covers max addr header
        encode_address_into(target, &mut plaintext);
        plaintext.extend_from_slice(data);

        // Generate salt into a stack buffer and derive subkey
        let mut salt = vec![0u8; salt_len];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        let subkey = self.cipher.derive_subkey(&self.master_key, &salt);

        // Encrypt in place (appends tag)
        encrypt_in_place_standalone(&self.cipher, &subkey, &ZERO_NONCE, &mut plaintext)?;

        // Build wire packet: salt + ciphertext_with_tag
        let mut packet = Vec::with_capacity(salt_len + plaintext.len());
        packet.extend_from_slice(&salt);
        packet.extend_from_slice(&plaintext);

        let n = self.inner.send(&packet).await?;
        debug!(
            "SS UDP sent {} bytes to {} (wire: {} bytes)",
            data.len(),
            target,
            n
        );
        Ok(data.len())
    }

    /// Receive a UDP datagram from the SS server, decrypt it, and return
    /// the decrypted payload (without the address header) and the source address.
    ///
    /// Returns `(data, address)` where address is the remote sender's address
    /// as encoded in the SS packet header.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let mut recv_buf = self.recv_buf.lock().await;
        let n = self.inner.recv(&mut recv_buf).await?;
        if n == 0 {
            return Err(anyhow!("SS UDP: received empty packet"));
        }

        let salt_len = self.cipher.salt_len();
        if n < salt_len + TAG_LEN {
            return Err(anyhow!(
                "SS UDP: packet too short ({} bytes, need at least {})",
                n,
                salt_len + TAG_LEN
            ));
        }

        let salt = &recv_buf[..salt_len];
        let mut ciphertext = recv_buf[salt_len..n].to_vec();

        // Derive per-packet subkey
        let subkey = self.cipher.derive_subkey(&self.master_key, salt);

        // Decrypt in place (removes tag)
        decrypt_in_place_standalone(&self.cipher, &subkey, &ZERO_NONCE, &mut ciphertext)?;

        // Parse the address header from the decrypted payload
        let (addr, header_len) = parse_address(&ciphertext)?;
        let data = &ciphertext[header_len..];

        let copy_len = std::cmp::min(data.len(), buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);

        debug!(
            "SS UDP recv {} bytes from {} (wire: {} bytes)",
            copy_len, addr, n
        );

        Ok((copy_len, addr))
    }

}

/// Implement `OutboundPacketConn` for `SsUdpSocket` — delegates to existing methods.
#[async_trait::async_trait]
impl crate::proxy::OutboundPacketConn for SsUdpSocket {
    async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize> {
        SsUdpSocket::send_to(self, data, target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        SsUdpSocket::recv_from(self, buf).await
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Parse a Shadowsocks address header from `data`.
/// Returns `(Address, bytes_consumed)`.
///
/// Format: `[addr_type(1)][addr_data][port(2 BE)]`
fn parse_address(data: &[u8]) -> Result<(Address, usize)> {
    if data.is_empty() {
        return Err(anyhow!("SS UDP: empty address data"));
    }

    match data[0] {
        0x01 => {
            // IPv4: 1 + 4 + 2 = 7 bytes
            if data.len() < 7 {
                return Err(anyhow!("SS UDP: truncated IPv4 address"));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((
                Address::Ip(SocketAddr::new(std::net::IpAddr::V4(ip), port)),
                7,
            ))
        }
        0x03 => {
            // Domain: 1 + 1(len) + domain + 2(port)
            if data.len() < 2 {
                return Err(anyhow!("SS UDP: truncated domain address"));
            }
            let domain_len = data[1] as usize;
            let total = 1 + 1 + domain_len + 2;
            if data.len() < total {
                return Err(anyhow!("SS UDP: truncated domain address data"));
            }
            let domain = String::from_utf8(data[2..2 + domain_len].to_vec())
                .map_err(|_| anyhow!("SS UDP: invalid domain encoding"))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok((Address::Domain(domain, port), total))
        }
        0x04 => {
            // IPv6: 1 + 16 + 2 = 19 bytes
            if data.len() < 19 {
                return Err(anyhow!("SS UDP: truncated IPv6 address"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                Address::Ip(SocketAddr::new(std::net::IpAddr::V6(ip), port)),
                19,
            ))
        }
        other => Err(anyhow!("SS UDP: unknown address type 0x{other:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::aead::{encode_address, generate_salt};
    use crate::common::addr::Address;

    #[test]
    fn test_parse_address_ipv4() {
        // addr_type=1, ip=1.2.3.4, port=443
        let data = [0x01, 1, 2, 3, 4, 0x01, 0xBB];
        let (addr, len) = parse_address(&data).unwrap();
        assert_eq!(len, 7);
        match addr {
            Address::Ip(sa) => {
                assert_eq!(
                    sa.ip(),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))
                );
                assert_eq!(sa.port(), 443);
            }
            _ => panic!("expected IP address"),
        }
    }

    #[test]
    fn test_parse_address_domain() {
        // addr_type=3, len=11, "example.com", port=8080
        let mut data = vec![0x03, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&8080u16.to_be_bytes());
        let (addr, len) = parse_address(&data).unwrap();
        assert_eq!(len, 15);
        match addr {
            Address::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 8080);
            }
            _ => panic!("expected domain address"),
        }
    }

    #[test]
    fn test_parse_address_ipv6() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        data.extend_from_slice(&80u16.to_be_bytes());
        let (addr, len) = parse_address(&data).unwrap();
        assert_eq!(len, 19);
        match addr {
            Address::Ip(sa) => {
                assert_eq!(sa.port(), 80);
            }
            _ => panic!("expected IP address"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = AeadCipher::Aes256Gcm;
        let key = vec![0x42u8; 32];
        let nonce = [0u8; 12];
        let original = b"hello world".to_vec();

        let mut data = original.clone();
        encrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_ne!(data, original); // encrypted != plaintext
        assert_eq!(data.len(), original.len() + TAG_LEN); // tag appended

        decrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_eq!(data, original); // back to original
    }

    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let cipher = AeadCipher::ChaCha20Poly1305;
        let key = vec![0xAB; 32];
        let nonce = [0u8; 12];
        let original = b"test data for chacha".to_vec();

        let mut data = original.clone();
        encrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        decrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_encrypt_decrypt_aes128() {
        let cipher = AeadCipher::Aes128Gcm;
        let key = vec![0xCD; 16];
        let nonce = [0u8; 12];
        let original = b"aes128 test".to_vec();

        let mut data = original.clone();
        encrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        decrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_full_packet_roundtrip() {
        // Simulate what send_to / recv_from does:
        // Build packet: salt + encrypt(addr_header + data)
        let cipher = AeadCipher::Aes256Gcm;
        let master_key = vec![0x55u8; 32];
        let target = Address::Domain("example.com".to_string(), 443);
        let payload = b"GET / HTTP/1.1\r\n";

        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&master_key, &salt);

        let addr_header = encode_address(&target);
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&addr_header);
        plaintext.extend_from_slice(payload);

        let original_plaintext = plaintext.clone();

        encrypt_in_place_standalone(&cipher, &subkey, &ZERO_NONCE, &mut plaintext).unwrap();

        // Now decrypt
        let subkey2 = cipher.derive_subkey(&master_key, &salt);
        decrypt_in_place_standalone(&cipher, &subkey2, &ZERO_NONCE, &mut plaintext).unwrap();
        assert_eq!(plaintext, original_plaintext);

        // Parse the address back
        let (addr, hdr_len) = parse_address(&plaintext).unwrap();
        assert_eq!(addr, target);
        assert_eq!(&plaintext[hdr_len..], payload);
    }
}
