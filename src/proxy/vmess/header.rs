//! VMess AEAD request header encoding (alterId = 0).
//!
//! 1:1 port of mihomo `transport/vmess/{user,aead,header,conn}.go`.
//!
//! The VMess AEAD header format replaces the legacy AES-128-CFB header with
//! an authenticated construction. Wire format (from `sealVMessAEADHeader`):
//! ```text
//! [AuthID: 16 bytes]                       -- AES-ECB(kdf(cmdKey,"AES Auth ID Encryption")[:16], time||rand||crc32)
//! [Header Length AEAD: 2 + 16 bytes]       -- AES-128-GCM, AAD = AuthID
//! [Connection Nonce: 8 bytes]              -- random, part of the header KDF path
//! [Header Payload AEAD: N + 16 bytes]      -- AES-128-GCM, AAD = AuthID
//! ```
//!
//! The header payload plaintext (from `conn.go sendRequest`) is:
//! ```text
//! [Version: 1 byte = 1]
//! [Request Body IV: 16 bytes random]
//! [Request Body Key: 16 bytes random]
//! [Response Auth V: 1 byte random]
//! [Option: 1 byte = OptionChunkStream (0x01)]  -- mihomo compat: conn.go only sets ChunkStream
//! [Padding<<4 | Security: 1 byte]
//! [Reserved: 1 byte = 0]
//! [Command: 1 byte, 1 = TCP, 2 = UDP]
//! [Port: 2 bytes big-endian]
//! [Address type: 1 = IPv4, 2 = Domain, 3 = IPv6]
//! [Address: variable]
//! [Padding: P random bytes]
//! [F: 4 bytes FNV1a-32 of above plaintext]
//! ```

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use hmac::Mac as HmacMac;
use md5::{Digest as _, Md5};
use rand::Rng;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = hmac::Hmac<Sha256>;

use crate::common::addr::Address;

/// VMess protocol version embedded in the header.
const VMESS_HEADER_VERSION: u8 = 1;

/// VMess command types.
pub const CMD_TCP: u8 = 0x01;

/// Address types. The encoder lives in `common::addr`; these are kept for the
/// wire-format tests below.
#[cfg(test)]
const ATYP_IPV4: u8 = 0x01;
#[cfg(test)]
const ATYP_DOMAIN: u8 = 0x02;

/// Option flags (vmess.go).
///
/// mihomo compat: `conn.go sendRequest` writes only `OptionChunkStream`.
/// It never sets ChunkMasking or GlobalPadding, so the wire framing is the
/// plain length-prefixed AEAD chunk stream (`aead.go`) with no Shake-based
/// size obfuscation or padding. We advertise exactly what we frame.
const OPT_CHUNK_STREAM: u8 = 0x01;

/// cmdKey magic suffix (user.go newID).
/// mihomo compat: cmdKey = MD5(uuid.Bytes() || this-magic-string).
const CMD_KEY_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

// KDF salt constants (header.go). Note the underscores in the `_Length`
// variants — these are the exact bytes mihomo feeds the KDF.
const KDF_SALT_AUTH_ID_ENCRYPTION: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_HEADER_PAYLOAD_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_PAYLOAD_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

// AEAD response-header salt constants (conn.go recvResponse).
const KDF_SALT_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_HEADER_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_HEADER_IV: &[u8] = b"AEAD Resp Header IV";

/// Response-header AEAD parameters (all AES-128-GCM, fixed nonces, no AAD).
///
/// mihomo compat: `conn.go recvResponse` derives these from `respBodyKey` /
/// `respBodyIV` (which are `SHA256(reqBodyKey)[:16]` / `SHA256(reqBodyIV)[:16]`).
/// The response header cipher is ALWAYS AES-128-GCM, independent of the body
/// `security`.
pub struct RespHeaderKeys {
    pub len_key: [u8; 16],
    pub len_iv: [u8; 12],
    pub payload_key: [u8; 16],
    pub payload_iv: [u8; 12],
}

/// Derive the AEAD response-header keys from the response body key/IV.
pub fn resp_header_keys(resp_body_key: &[u8; 16], resp_body_iv: &[u8; 16]) -> RespHeaderKeys {
    fn key16(key: &[u8; 16], salt: &[u8]) -> [u8; 16] {
        let out = kdf(key, &[salt]);
        let mut a = [0u8; 16];
        a.copy_from_slice(&out[..16]);
        a
    }
    fn nonce12(key: &[u8; 16], salt: &[u8]) -> [u8; 12] {
        let out = kdf(key, &[salt]);
        let mut a = [0u8; 12];
        a.copy_from_slice(&out[..12]);
        a
    }
    RespHeaderKeys {
        len_key: key16(resp_body_key, KDF_SALT_RESP_HEADER_LEN_KEY),
        len_iv: nonce12(resp_body_iv, KDF_SALT_RESP_HEADER_LEN_IV),
        payload_key: key16(resp_body_key, KDF_SALT_RESP_HEADER_KEY),
        payload_iv: nonce12(resp_body_iv, KDF_SALT_RESP_HEADER_IV),
    }
}

/// `SHA256(x)[..16]` — used to derive response body key/IV from the request
/// body key/IV in AEAD mode (conn.go newConn).
pub fn sha256_16(x: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(x);
    let out = h.finalize();
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[..16]);
    r
}

/// Security types (low 4 bits of the security byte, vmess.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
    None = 5,
}

impl VmessSecurity {
    /// Parse from config string.
    ///
    /// mihomo compat: `vmess.go NewClient` maps "auto" to CHACHA20POLY1305 on
    /// most arches but AES128GCM on amd64/arm64/s390x. Our targets are
    /// x86_64 and aarch64, so "auto" is always AES-128-GCM.
    pub fn from_str(s: &str) -> Self {
        match s {
            "aes-128-gcm" => VmessSecurity::Aes128Gcm,
            "chacha20-poly1305" => VmessSecurity::Chacha20Poly1305,
            "none" | "zero" => VmessSecurity::None,
            // "auto" or anything else => AES-128-GCM (amd64/arm64 targets).
            _ => VmessSecurity::Aes128Gcm,
        }
    }
}

/// The result of encoding a VMess AEAD request header.
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

/// mihomo's nested-HMAC KDF (header.go `kdf` + `hMacCreator`).
///
/// The innermost HMAC is keyed with "VMess AEAD KDF" over SHA-256. Each path
/// element becomes the key of an *outer* HMAC whose hash function is the
/// *inner* HMAC created so far. The final `key` is written into the outermost
/// HMAC. This is NOT a sequential chain of `HMAC(prev, path)`.
///
/// Go's `hmac.New(h.parent.Create, h.value)` uses the parent HMAC as the
/// block-hash constructor. Because generic recursion over the `Mac` trait is
/// awkward in Rust, we implement the HMAC nesting directly (textbook
/// ipad/opad construction) so the byte output is identical.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    // Chain of keys from innermost ("VMess AEAD KDF") outward.
    let mut keys: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    keys.push(KDF_SALT_VMESS_AEAD_KDF);
    keys.extend_from_slice(path);
    nested_hmac(&keys, key)
}

/// Evaluate the nested HMAC. `keys[0]` is the innermost SHA-256 HMAC key;
/// `keys[len-1]` is the outermost. `message` is fed to the outermost HMAC.
///
/// HMAC with key K over hash function h(x):
///   h((K0 ^ opad) || h((K0 ^ ipad) || message))
/// where h for layer 0 is SHA-256, and for deeper layers is the HMAC formed by
/// the remaining inner keys. Every layer's block size is 64 (SHA-256's), which
/// is what Go's `hmac.Hash.BlockSize()` reports transitively.
fn nested_hmac(keys: &[&[u8]], message: &[u8]) -> [u8; 32] {
    if keys.len() == 1 {
        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(keys[0])
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(message);
        let out = mac.finalize().into_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        return r;
    }

    const BLOCK: usize = 64;
    let inner_keys = &keys[..keys.len() - 1];
    let key = keys[keys.len() - 1];

    // K0: hash an over-long key through the inner hash function; else zero-pad.
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = nested_hmac(inner_keys, key);
        k0[..hashed.len()].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner_msg = Vec::with_capacity(BLOCK + message.len());
    inner_msg.extend_from_slice(&ipad);
    inner_msg.extend_from_slice(message);
    let inner = nested_hmac(inner_keys, &inner_msg);

    let mut outer_msg = Vec::with_capacity(BLOCK + inner.len());
    outer_msg.extend_from_slice(&opad);
    outer_msg.extend_from_slice(&inner);
    nested_hmac(inner_keys, &outer_msg)
}

/// Compute the VMess cmdKey: `MD5(uuid || magic-suffix)` (user.go newID).
fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(CMD_KEY_MAGIC);
    let result = hasher.finalize();
    let mut k = [0u8; 16];
    k.copy_from_slice(&result);
    k
}

/// CRC32 (IEEE, reflected) — matches Go's `hash/crc32.ChecksumIEEE`.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Create the 16-byte AuthID (header.go `createAuthID`).
///
/// buf = BE(time_i64) || rand(4) || BE(crc32_ieee(time||rand)); then
/// AES-ECB-encrypt one block with key = kdf(cmdKey, "AES Auth ID Encryption")[:16].
fn create_auth_id(cmd_key: &[u8; 16], time: i64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&time.to_be_bytes());
    rand::thread_rng().fill(&mut buf[8..12]);
    let crc = crc32_ieee(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());

    let key = kdf(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION]);
    let cipher = aes::Aes128::new_from_slice(&key[..16]).expect("AES-128 key length is valid");
    let mut block = aes::Block::clone_from_slice(&buf);
    cipher.encrypt_block(&mut block);
    let mut result = [0u8; 16];
    result.copy_from_slice(&block);
    result
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

/// The VMess address header is `port (BE u16) || atyp || addr` (conn.go) —
/// the same framing VLESS uses.
use crate::common::addr::encode_vmess as encode_address;

/// Seal the plaintext header into the AEAD wire format (header.go
/// `sealVMessAEADHeader`).
fn seal_vmess_aead_header(cmd_key: &[u8; 16], data: &[u8], time: i64) -> Vec<u8> {
    let auth_id = create_auth_id(cmd_key, time);

    let mut connection_nonce = [0u8; 8];
    rand::thread_rng().fill(&mut connection_nonce);

    let len_be = (data.len() as u16).to_be_bytes();

    // Header Length AEAD.
    let length_key = {
        let k = kdf(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_LEN_KEY, &auth_id, &connection_nonce],
        );
        let mut key = [0u8; 16];
        key.copy_from_slice(&k[..16]);
        key
    };
    let length_nonce = {
        let k = kdf(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_LEN_IV, &auth_id, &connection_nonce],
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&k[..12]);
        nonce
    };
    let encrypted_length = Aes128Gcm::new_from_slice(&length_key)
        .expect("AES-128-GCM key length is valid")
        .encrypt(
            Nonce::from_slice(&length_nonce),
            aes_gcm::aead::Payload {
                msg: &len_be,
                aad: &auth_id,
            },
        )
        .expect("AES-128-GCM encryption should not fail");

    // Header Payload AEAD.
    let payload_key = {
        let k = kdf(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_KEY, &auth_id, &connection_nonce],
        );
        let mut key = [0u8; 16];
        key.copy_from_slice(&k[..16]);
        key
    };
    let payload_nonce = {
        let k = kdf(
            cmd_key,
            &[KDF_SALT_HEADER_PAYLOAD_IV, &auth_id, &connection_nonce],
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&k[..12]);
        nonce
    };
    let encrypted_payload = Aes128Gcm::new_from_slice(&payload_key)
        .expect("AES-128-GCM key length is valid")
        .encrypt(
            Nonce::from_slice(&payload_nonce),
            aes_gcm::aead::Payload {
                msg: data,
                aad: &auth_id,
            },
        )
        .expect("AES-128-GCM encryption should not fail");

    // outputBuffer: authID || encrypted_length || connection_nonce || encrypted_payload
    let mut wire = Vec::with_capacity(16 + encrypted_length.len() + 8 + encrypted_payload.len());
    wire.extend_from_slice(&auth_id);
    wire.extend_from_slice(&encrypted_length);
    wire.extend_from_slice(&connection_nonce);
    wire.extend_from_slice(&encrypted_payload);
    wire
}

/// Encode a VMess AEAD request header (alterId=0). Ports `conn.go sendRequest`
/// (AEAD branch) + `sealVMessAEADHeader`.
pub fn encode_request_header(
    uuid: &[u8; 16],
    cmd: u8,
    security: VmessSecurity,
    target: &Address,
) -> VmessHeaderResult {
    let mut rng = rand::thread_rng();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // newConn: randBytes[33] -> reqBodyIV(16) reqBodyKey(16) respV(1).
    let mut body_iv = [0u8; 16];
    let mut body_key = [0u8; 16];
    rng.fill(&mut body_iv);
    rng.fill(&mut body_key);
    let response_auth: u8 = rng.gen();

    // Padding P = randv2.IntN(16), 0..15.
    let padding_len: u8 = (rng.gen::<u8>()) % 16;
    let security_byte = (padding_len << 4) | (security as u8);

    let addr_bytes = encode_address(target);

    // Plaintext header (conn.go sendRequest, buf before AEAD sealing).
    let mut header_plaintext = Vec::with_capacity(
        1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + addr_bytes.len() + padding_len as usize + 4,
    );
    header_plaintext.push(VMESS_HEADER_VERSION);
    header_plaintext.extend_from_slice(&body_iv);
    header_plaintext.extend_from_slice(&body_key);
    header_plaintext.push(response_auth);
    header_plaintext.push(OPT_CHUNK_STREAM);
    header_plaintext.push(security_byte);
    header_plaintext.push(0x00); // reserved
    header_plaintext.push(cmd);
    header_plaintext.extend_from_slice(&addr_bytes);
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill(&mut padding[..]);
        header_plaintext.extend_from_slice(&padding);
    }
    let checksum = fnv1a32(&header_plaintext);
    header_plaintext.extend_from_slice(&checksum.to_be_bytes());

    let ckey = cmd_key(uuid);
    let wire = seal_vmess_aead_header(&ckey, &header_plaintext, timestamp);

    VmessHeaderResult {
        header_bytes: wire,
        body_key,
        body_iv,
        response_auth,
        security,
    }
}

// mihomo compat: UUID parsing is identical across VMess/VLESS; reuse the VLESS
// copy rather than duplicating it.
pub use crate::proxy::vless::header::parse_uuid;

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
    fn crc32_ieee_known() {
        // Standard IEEE CRC-32 test vector: "123456789" -> 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
    }

    /// cmdKey MUST be MD5(uuid || magic-suffix), NOT plain MD5(uuid).
    #[test]
    fn cmd_key_magic_suffix() {
        let uuid = [0u8; 16];
        let ck = cmd_key(&uuid);

        // Recompute by hand: MD5(uuid || magic).
        let mut h = Md5::new();
        h.update(uuid);
        h.update(CMD_KEY_MAGIC);
        let expected = h.finalize();
        assert_eq!(&ck[..], &expected[..]);

        // Must differ from plain MD5(uuid) (the old broken behavior).
        let mut h2 = Md5::new();
        h2.update(uuid);
        let plain = h2.finalize();
        assert_ne!(&ck[..], &plain[..]);
    }

    /// Assert the exact cmdKey magic bytes never drift.
    #[test]
    fn cmd_key_magic_bytes() {
        assert_eq!(CMD_KEY_MAGIC, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    }

    /// Assert exact salt-label bytes (underscores in the `_Length` variants).
    #[test]
    fn kdf_salt_label_bytes() {
        assert_eq!(KDF_SALT_AUTH_ID_ENCRYPTION, b"AES Auth ID Encryption");
        assert_eq!(KDF_SALT_VMESS_AEAD_KDF, b"VMess AEAD KDF");
        assert_eq!(KDF_SALT_HEADER_PAYLOAD_KEY, b"VMess Header AEAD Key");
        assert_eq!(KDF_SALT_HEADER_PAYLOAD_IV, b"VMess Header AEAD Nonce");
        assert_eq!(
            KDF_SALT_HEADER_PAYLOAD_LEN_KEY,
            b"VMess Header AEAD Key_Length"
        );
        assert_eq!(
            KDF_SALT_HEADER_PAYLOAD_LEN_IV,
            b"VMess Header AEAD Nonce_Length"
        );
    }

    /// KDF regression against an independent reference implementation of the
    /// mihomo nested-HMAC algorithm.
    #[test]
    fn kdf_single_path_matches_reference() {
        let key = b"Demo Key for Auth ID Test";
        assert_eq!(
            kdf(key, &[b"Demo Path"]).to_vec(),
            reference_kdf(key, &[b"Demo Path"])
        );
    }

    #[test]
    fn kdf_multi_path_matches_reference() {
        let key = b"cmdkey-16-bytes!";
        let paths: &[&[u8]] = &[
            b"VMess Header AEAD Key_Length",
            b"authid--16bytes!",
            b"nonce8!!",
        ];
        assert_eq!(kdf(key, paths).to_vec(), reference_kdf(key, paths));
    }

    /// Hardcoded regression vectors produced by an INDEPENDENT Python
    /// implementation of V2Ray/mihomo's nested-HMAC KDF (recursive HMAC where
    /// each layer's hash function is the layer below, innermost = HMAC-SHA256
    /// keyed by "VMess AEAD KDF"). If the Rust KDF drifts, these break.
    #[test]
    fn kdf_independent_vectors() {
        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        assert_eq!(
            hex(&kdf(b"Demo Key for Auth ID Test", &[b"Demo Path"])),
            "fc8821dc540905b50ada1ee7de7913d948c1428e77a9883a3fec71a5c855e4a4"
        );
        assert_eq!(
            hex(&kdf(
                b"cmdkey-16-bytes!",
                &[
                    b"VMess Header AEAD Key_Length",
                    b"authid--16bytes!",
                    b"nonce8!!"
                ]
            )),
            "ab06f85012cddc426f0cb3e1e8f7f1eef7b81fd328281046a229255019c09e9b"
        );
        assert_eq!(
            hex(&kdf(b"respBodyKey-16by", &[])),
            "8084c2b37071ad062355e7ac9f2b9fcfbd7ce33ebae209d75398e05d2ec93622"
        );
    }

    #[test]
    fn kdf_no_path_matches_reference() {
        // Empty path: just HMAC-SHA256("VMess AEAD KDF", key).
        let key = b"respBodyKey-16by";
        assert_eq!(kdf(key, &[]).to_vec(), reference_kdf(key, &[]));

        // And directly: HMAC-SHA256("VMess AEAD KDF", key).
        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(b"VMess AEAD KDF").unwrap();
        mac.update(key);
        assert_eq!(kdf(key, &[]).to_vec(), mac.finalize().into_bytes().to_vec());
    }

    /// Independent reference implementation of mihomo's nested-HMAC KDF, written
    /// from scratch to cross-check the optimized `kdf`. Mirrors Go's
    /// `hMacCreator` semantics exactly.
    fn reference_kdf(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = vec![b"VMess AEAD KDF".to_vec()];
        for p in path {
            keys.push(p.to_vec());
        }
        ref_hmac(&keys, key).to_vec()
    }

    /// Recursive HMAC where layer i>0's hash function is layer i-1's HMAC, and
    /// layer 0 is HMAC-SHA256. Textbook ipad/opad construction.
    fn ref_hmac(keys: &[Vec<u8>], msg: &[u8]) -> [u8; 32] {
        if keys.len() == 1 {
            let mut mac = <HmacSha256 as HmacMac>::new_from_slice(&keys[0]).unwrap();
            mac.update(msg);
            let mut r = [0u8; 32];
            r.copy_from_slice(&mac.finalize().into_bytes());
            return r;
        }
        const BLOCK: usize = 64;
        let inner = &keys[..keys.len() - 1];
        let key = &keys[keys.len() - 1];
        let mut k0 = [0u8; BLOCK];
        if key.len() > BLOCK {
            let h = ref_hmac(inner, key);
            k0[..h.len()].copy_from_slice(&h);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }
        let mut im = ipad.to_vec();
        im.extend_from_slice(msg);
        let inner_digest = ref_hmac(inner, &im);
        let mut om = opad.to_vec();
        om.extend_from_slice(&inner_digest);
        ref_hmac(inner, &om)
    }

    #[test]
    fn auth_id_deterministic_structure() {
        let ck = [0x11u8; 16];
        let a = create_auth_id(&ck, 1_700_000_000);
        assert_eq!(a.len(), 16);
        assert_ne!(a, [0u8; 16]);
    }

    /// AuthID must be an AES-ECB block over time||rand||crc32, decryptable back
    /// to a buffer whose last 4 bytes are the CRC32 of the first 12.
    #[test]
    fn auth_id_crc32_roundtrip() {
        use aes::cipher::BlockDecrypt;
        let ck = [0x22u8; 16];
        let time: i64 = 1_699_999_999;
        let auth = create_auth_id(&ck, time);

        // Decrypt with the same key derivation to recover the plaintext block.
        let key = kdf(&ck, &[KDF_SALT_AUTH_ID_ENCRYPTION]);
        let cipher = aes::Aes128::new_from_slice(&key[..16]).unwrap();
        let mut block = aes::Block::clone_from_slice(&auth);
        cipher.decrypt_block(&mut block);

        // time matches.
        assert_eq!(&block[..8], &time.to_be_bytes());
        // crc32 of first 12 bytes == last 4 bytes.
        let crc = crc32_ieee(&block[..12]);
        assert_eq!(&block[12..16], &crc.to_be_bytes());
    }

    #[test]
    fn encode_request_header_layout() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        let target = Address::Domain("example.com".to_string(), 443);
        let result = encode_request_header(&uuid, CMD_TCP, VmessSecurity::Aes128Gcm, &target);

        // Wire = authID(16) + encLen(2+16) + connNonce(8) + encPayload(N+16).
        // Minimal plaintext ("example.com"=11, padding 0):
        // 1+16+16+1+1+1+1+1 + (2+1+1+11) + 0 + 4 = 58; wire >= 16+18+8+(58+16)=116.
        assert!(result.header_bytes.len() >= 16 + 18 + 8 + (58 + 16));
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
        assert_eq!(&encoded[0..2], &8443u16.to_be_bytes());
        assert_eq!(encoded[2], ATYP_DOMAIN);
        assert_eq!(encoded[3], 8);
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
