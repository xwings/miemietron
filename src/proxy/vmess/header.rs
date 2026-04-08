//! VMess AEAD request header encoding (alterId = 0).
//!
//! The VMess AEAD header format replaces the legacy AES-128-CFB header with
//! an authenticated construction based on AES-128-GCM.
//!
//! Wire format:
//! ```text
//! [Auth Info: 16 bytes]                    -- HMAC-MD5(key=uuid, data=timestamp)
//! [Connection Nonce: 8 bytes]              -- random, used for header key derivation
//! [Header Length: 2 bytes AES-128-GCM encrypted + 16 byte AEAD tag]
//! [Header Payload: N bytes AES-128-GCM encrypted + 16 byte AEAD tag]
//! ```
//!
//! The header payload (before encryption) contains:
//! ```text
//! [Version: 1 byte = 1]
//! [Request Body IV: 16 bytes random]
//! [Request Body Key: 16 bytes random]
//! [Response Auth V: 1 byte random]
//! [Option: 1 byte, bit 0 = chunk stream, bit 2 = chunk masking, bit 3 = global padding]
//! [Security + Padding: 1 byte, high 4 bits = padding len P, low 4 bits = security]
//! [Reserved: 1 byte = 0]
//! [Command: 1 byte, 1 = TCP, 2 = UDP]
//! [Port: 2 bytes big-endian]
//! [Address type: 1 = IPv4, 2 = Domain, 3 = IPv6]
//! [Address: variable]
//! [Padding: P random bytes]
//! [F: 4 bytes FNV1a-32 of above plaintext]
//! ```

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use hmac::Mac as HmacMac;
use md5::{Digest as _, Md5};
use rand::Rng;
use sha2::Sha256;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = hmac::Hmac<Sha256>;
type HmacMd5 = hmac::Hmac<md5::Md5>;

use crate::common::addr::Address;

/// VMess protocol version embedded in the header.
const VMESS_HEADER_VERSION: u8 = 1;

/// VMess command types.
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

/// Address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// Option flags.
/// Bit 0: standard chunk format (must be set for AEAD mode).
/// Bit 2: chunk masking with ShakeSizeParser.
/// Bit 3: global padding.
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;

/// Security types (low 4 bits of the security byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
    None = 5,
}

impl VmessSecurity {
    /// Parse from config string. "auto" defaults to AES-128-GCM.
    pub fn from_str(s: &str) -> Self {
        match s {
            "aes-128-gcm" => VmessSecurity::Aes128Gcm,
            "chacha20-poly1305" => VmessSecurity::Chacha20Poly1305,
            "none" | "zero" => VmessSecurity::None,
            // "auto" or anything else => AES-128-GCM
            _ => VmessSecurity::Aes128Gcm,
        }
    }
}

/// The result of encoding a VMess AEAD request header.
/// Contains both the serialised header bytes to send on the wire and the
/// body encryption parameters the caller needs for the data stream.
pub struct VmessHeaderResult {
    /// Encoded header bytes to send over the wire.
    pub header_bytes: Vec<u8>,
    /// Body encryption key (16 bytes).
    pub body_key: [u8; 16],
    /// Body encryption IV (16 bytes).
    pub body_iv: [u8; 16],
    /// Response authentication byte (V).
    pub response_auth: u8,
    /// Security method.
    pub security: VmessSecurity,
}

/// KDF with label, using HMAC-SHA256 in a recursive construction.
/// This mirrors V2Ray's `kdf` function.
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let mut current = key.to_vec();
    for path in paths {
        let mut hmac = <HmacSha256 as HmacMac>::new_from_slice(&current)
            .expect("HMAC-SHA256 accepts any key length");
        hmac.update(path);
        let result = hmac.finalize().into_bytes();
        current = result.to_vec();
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&current);
    out
}

/// Create the 16-byte authentication info: HMAC-MD5(key=uuid, data=timestamp_be).
fn create_auth_info(uuid: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut hmac =
        <HmacMd5 as HmacMac>::new_from_slice(uuid).expect("HMAC-MD5 accepts any key length");
    hmac.update(&timestamp.to_be_bytes());
    let result = hmac.finalize().into_bytes();
    let mut auth = [0u8; 16];
    auth.copy_from_slice(&result);
    auth
}

/// FNV1a-32 hash.
fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Encode a VMess address (similar to SOCKS5 address encoding).
fn encode_address(addr: &Address) -> Vec<u8> {
    let mut buf = Vec::new();
    // Port comes first in VMess header (before address type).
    buf.extend_from_slice(&addr.port().to_be_bytes());

    match addr {
        Address::Ip(sockaddr) => match sockaddr.ip() {
            IpAddr::V4(ipv4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&ipv6.octets());
            }
        },
        Address::Domain(domain, _port) => {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
    }
    buf
}

/// Encode a VMess AEAD request header.
///
/// This implements the alterId=0 AEAD header format as specified in
/// the V2Ray/VMess protocol documentation.
///
/// Returns a `VmessHeaderResult` containing the wire bytes and the
/// body encryption parameters.
pub fn encode_request_header(
    uuid: &[u8; 16],
    cmd: u8,
    security: VmessSecurity,
    target: &Address,
) -> VmessHeaderResult {
    let mut rng = rand::thread_rng();

    // Current timestamp (seconds since epoch).
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // --- Auth Info (16 bytes) ---
    let auth_info = create_auth_info(uuid, timestamp);

    // --- Random connection nonce (8 bytes) ---
    let mut connection_nonce = [0u8; 8];
    rng.fill(&mut connection_nonce);

    // --- Build header plaintext ---
    let mut body_iv = [0u8; 16];
    let mut body_key = [0u8; 16];
    rng.fill(&mut body_iv);
    rng.fill(&mut body_key);

    let response_auth: u8 = rng.gen();

    let options = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING;

    // Padding length (0-15 random bytes).
    let padding_len: u8 = rng.gen::<u8>() % 16;
    let security_byte = (padding_len << 4) | (security as u8);

    let addr_bytes = encode_address(target);

    // Total plaintext header size:
    //   1 (version) + 16 (body IV) + 16 (body key) + 1 (response auth)
    //   + 1 (options) + 1 (security) + 1 (reserved) + 1 (command)
    //   + addr_bytes.len() + padding_len + 4 (FNV1a checksum)
    let header_len = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + addr_bytes.len() + padding_len as usize + 4;
    let mut header_plaintext = Vec::with_capacity(header_len);

    header_plaintext.push(VMESS_HEADER_VERSION);
    header_plaintext.extend_from_slice(&body_iv);
    header_plaintext.extend_from_slice(&body_key);
    header_plaintext.push(response_auth);
    header_plaintext.push(options);
    header_plaintext.push(security_byte);
    header_plaintext.push(0x00); // reserved
    header_plaintext.push(cmd);
    header_plaintext.extend_from_slice(&addr_bytes);
    // Random padding.
    let mut padding = vec![0u8; padding_len as usize];
    rng.fill(&mut padding[..]);
    header_plaintext.extend_from_slice(&padding);
    // FNV1a-32 checksum.
    let checksum = fnv1a32(&header_plaintext);
    header_plaintext.extend_from_slice(&checksum.to_be_bytes());

    // --- AEAD header encryption ---
    // Derive the "cmd key" from UUID: MD5(uuid_bytes)
    let cmd_key = {
        let mut hasher = Md5::new();
        hasher.update(uuid);
        let result = hasher.finalize();
        let mut k = [0u8; 16];
        k.copy_from_slice(&result);
        k
    };

    // EAEADHeaderLengthEncryptionKey = KDF(cmdKey, "VMess AEAD KDF" | "VMess Header AEAD Key Length Encryption" | auth_info | connection_nonce)
    // We use the KDF to derive 16-byte keys (take first 16 bytes of the 32-byte HMAC-SHA256 output).
    let header_length_key = {
        let k = kdf(
            &cmd_key,
            &[
                b"VMess AEAD KDF",
                b"VMess Header AEAD Key Length Encryption",
                &auth_info,
                &connection_nonce,
            ],
        );
        let mut key = [0u8; 16];
        key.copy_from_slice(&k[..16]);
        key
    };

    let header_length_nonce = {
        let k = kdf(
            &cmd_key,
            &[
                b"VMess AEAD KDF",
                b"VMess Header AEAD Nonce Length Encryption",
                &auth_info,
                &connection_nonce,
            ],
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&k[..12]);
        nonce
    };

    let header_payload_key = {
        let k = kdf(
            &cmd_key,
            &[
                b"VMess AEAD KDF",
                b"VMess Header AEAD Key Encryption",
                &auth_info,
                &connection_nonce,
            ],
        );
        let mut key = [0u8; 16];
        key.copy_from_slice(&k[..16]);
        key
    };

    let header_payload_nonce = {
        let k = kdf(
            &cmd_key,
            &[
                b"VMess AEAD KDF",
                b"VMess Header AEAD Nonce Encryption",
                &auth_info,
                &connection_nonce,
            ],
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&k[..12]);
        nonce
    };

    // Encrypt the header length (2 bytes, big-endian) with AES-128-GCM.
    let header_len_be = (header_plaintext.len() as u16).to_be_bytes();
    let length_cipher =
        Aes128Gcm::new_from_slice(&header_length_key).expect("AES-128-GCM key length is valid");
    let encrypted_length = length_cipher
        .encrypt(
            Nonce::from_slice(&header_length_nonce),
            aes_gcm::aead::Payload {
                msg: &header_len_be,
                aad: &auth_info,
            },
        )
        .expect("AES-128-GCM encryption should not fail");

    // Encrypt the header payload with AES-128-GCM.
    let payload_cipher =
        Aes128Gcm::new_from_slice(&header_payload_key).expect("AES-128-GCM key length is valid");
    let encrypted_payload = payload_cipher
        .encrypt(
            Nonce::from_slice(&header_payload_nonce),
            aes_gcm::aead::Payload {
                msg: &header_plaintext,
                aad: &auth_info,
            },
        )
        .expect("AES-128-GCM encryption should not fail");

    // --- Assemble final wire bytes ---
    // [auth_info: 16][connection_nonce: 8][encrypted_length: 2+16][encrypted_payload: N+16]
    let mut wire = Vec::with_capacity(16 + 8 + encrypted_length.len() + encrypted_payload.len());
    wire.extend_from_slice(&auth_info);
    wire.extend_from_slice(&connection_nonce);
    wire.extend_from_slice(&encrypted_length);
    wire.extend_from_slice(&encrypted_payload);

    VmessHeaderResult {
        header_bytes: wire,
        body_key,
        body_iv,
        response_auth,
        security,
    }
}

/// Parse a UUID string into 16 raw bytes.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

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
    fn parse_uuid_invalid() {
        assert!(parse_uuid("1234").is_err());
        assert!(parse_uuid("GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG").is_err());
    }

    #[test]
    fn fnv1a32_empty() {
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
    }

    #[test]
    fn fnv1a32_known() {
        // Known FNV-1a test vector for "foobar".
        assert_eq!(fnv1a32(b"foobar"), 0xbf9c_f968);
    }

    #[test]
    fn auth_info_deterministic() {
        let uuid = [0u8; 16];
        let ts = 1700000000u64;
        let a1 = create_auth_info(&uuid, ts);
        let a2 = create_auth_info(&uuid, ts);
        assert_eq!(a1, a2);
        assert_ne!(a1, [0u8; 16]); // should not be all zeros
    }

    #[test]
    fn encode_request_header_produces_output() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        let target = Address::Domain("example.com".to_string(), 443);
        let result = encode_request_header(&uuid, CMD_TCP, VmessSecurity::Aes128Gcm, &target);

        // Auth info (16) + connection nonce (8) + encrypted length (2+16) + encrypted payload (N+16)
        // Minimum header plaintext: 1+16+16+1+1+1+1+1+2+1+1+11+0+4 = 57 bytes
        // Wire: 16 + 8 + 18 + (57 + 16) = 115 minimum
        assert!(result.header_bytes.len() >= 115);
        assert_ne!(result.body_key, [0u8; 16]);
        assert_ne!(result.body_iv, [0u8; 16]);
    }

    #[test]
    fn encode_request_header_ipv4() {
        let uuid = [0xAA; 16];
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80));
        let target = Address::Ip(sock);
        let result =
            encode_request_header(&uuid, CMD_TCP, VmessSecurity::Chacha20Poly1305, &target);
        assert!(!result.header_bytes.is_empty());
        assert_eq!(result.security, VmessSecurity::Chacha20Poly1305);
    }

    #[test]
    fn encode_address_domain() {
        let addr = Address::Domain("test.com".to_string(), 8443);
        let encoded = encode_address(&addr);
        // Port first (2 bytes), then address type, then len, then domain.
        assert_eq!(&encoded[0..2], &8443u16.to_be_bytes());
        assert_eq!(encoded[2], ATYP_DOMAIN);
        assert_eq!(encoded[3], 8); // "test.com".len()
        assert_eq!(&encoded[4..12], b"test.com");
    }

    #[test]
    fn encode_address_ipv4() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));
        let addr = Address::Ip(sock);
        let encoded = encode_address(&addr);
        assert_eq!(&encoded[0..2], &443u16.to_be_bytes());
        assert_eq!(encoded[2], ATYP_IPV4);
        assert_eq!(&encoded[3..7], &[10, 0, 0, 1]);
    }

    #[test]
    fn security_from_str() {
        assert_eq!(VmessSecurity::from_str("auto"), VmessSecurity::Aes128Gcm);
        assert_eq!(
            VmessSecurity::from_str("aes-128-gcm"),
            VmessSecurity::Aes128Gcm
        );
        assert_eq!(
            VmessSecurity::from_str("chacha20-poly1305"),
            VmessSecurity::Chacha20Poly1305
        );
        assert_eq!(VmessSecurity::from_str("none"), VmessSecurity::None);
    }
}
