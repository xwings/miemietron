use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use digest::Digest;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Aes192Gcm = aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;

/// Largest payload chunk the writer emits. Only the writer is capped: sing's
/// reader takes any 16-bit length (`internal/shadowio/reader.go` readBuffer).
/// Legacy AEAD: `shadowaead.MaxPacketSize`.
const MAX_PAYLOAD_SIZE: usize = 0x3FFF;
/// SS2022: `buf.BufferSize - PacketLengthBufferSize - Overhead*2` = 32734
/// (`shadowaead_2022/method.go` writeRequest).
const MAX_PAYLOAD_SIZE_2022: usize = 0x7FDE;

/// AEAD tag size for all supported ciphers (16 bytes).
pub(super) const TAG_LEN: usize = 16;

/// Nonce size of the session nonce counter (12 bytes).
pub(super) const NONCE_LEN: usize = 12;

/// Supported AEAD cipher types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadCipher {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    // SS2022 ciphers (use BLAKE3 KDF, base64 key)
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
    Blake3ChaCha20Poly1305,
}

impl AeadCipher {
    /// Parse cipher name from config string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "aes-128-gcm" => Some(AeadCipher::Aes128Gcm),
            "aes-192-gcm" => Some(AeadCipher::Aes192Gcm),
            "aes-256-gcm" => Some(AeadCipher::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(AeadCipher::ChaCha20Poly1305),
            "xchacha20-ietf-poly1305" => Some(AeadCipher::XChaCha20Poly1305),
            "2022-blake3-aes-128-gcm" => Some(AeadCipher::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(AeadCipher::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha20-ietf-poly1305" => {
                Some(AeadCipher::Blake3ChaCha20Poly1305)
            }
            _ => None,
        }
    }

    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            AeadCipher::Aes128Gcm | AeadCipher::Blake3Aes128Gcm => 16,
            AeadCipher::Aes192Gcm => 24,
            AeadCipher::Aes256Gcm
            | AeadCipher::ChaCha20Poly1305
            | AeadCipher::XChaCha20Poly1305
            | AeadCipher::Blake3Aes256Gcm
            | AeadCipher::Blake3ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes (same as key length for AEAD ciphers).
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    /// Whether this is an SS2022 cipher (uses BLAKE3 KDF + base64 key).
    pub fn is_ss2022(&self) -> bool {
        matches!(
            self,
            AeadCipher::Blake3Aes128Gcm
                | AeadCipher::Blake3Aes256Gcm
                | AeadCipher::Blake3ChaCha20Poly1305
        )
    }

    /// Derive a subkey from the master key and salt.
    /// SS2022 uses BLAKE3; legacy uses HKDF-SHA1.
    pub fn derive_subkey(&self, key: &[u8], salt: &[u8]) -> Vec<u8> {
        if self.is_ss2022() {
            // SS2022: BLAKE3 key derivation
            // subkey = BLAKE3::derive_key("shadowsocks 2022 session subkey", key || salt)
            let mut out = vec![0u8; self.key_len()];
            let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
            hasher.update(key);
            hasher.update(salt);
            hasher.finalize_xof().fill(&mut out);
            out
        } else {
            hkdf_sha1(key, salt, b"ss-subkey", self.key_len())
        }
    }
}

/// Derive the master key from a password using EVP_BytesToKey (MD5-based).
///
/// This is the legacy key derivation used by Shadowsocks AEAD ciphers.
/// count = ceil(key_len / 16)
/// d[0] = MD5(password)
/// d[i] = MD5(d[i-1] || password) for i > 0
/// key = d[0] || d[1] || ... truncated to key_len
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    const MD5_LEN: usize = 16;
    let count = key_len.div_ceil(MD5_LEN);
    let mut result = Vec::with_capacity(count * MD5_LEN);
    let mut prev = [0u8; MD5_LEN]; // stack array instead of Vec

    for i in 0..count {
        let mut hasher = md5::Md5::new();
        if i > 0 {
            hasher.update(prev);
        }
        hasher.update(password);
        let hash = hasher.finalize();
        prev.copy_from_slice(&hash);
        result.extend_from_slice(&prev);
    }

    result.truncate(key_len);
    result
}

/// HKDF-SHA1 key derivation (used to derive per-session subkeys).
fn hkdf_sha1(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let s = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = ring::hmac::sign(&s, ikm);
    // Compute HMAC key once outside the loop (prk is constant).
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, prk.as_ref());

    let mut okm = Vec::with_capacity(out_len);
    // Reuse buffers across iterations instead of allocating fresh Vecs each loop.
    let mut prev_tag = Vec::with_capacity(20); // SHA1 output is 20 bytes
    let mut data = Vec::with_capacity(20 + info.len() + 1);
    let mut counter: u8 = 1;

    while okm.len() < out_len {
        data.clear();
        data.extend_from_slice(&prev_tag);
        data.extend_from_slice(info);
        data.push(counter);
        let tag = ring::hmac::sign(&key, &data);
        prev_tag.clear();
        prev_tag.extend_from_slice(tag.as_ref());
        okm.extend_from_slice(tag.as_ref());
        counter += 1;
    }

    okm.truncate(out_len);
    okm
}

/// The shadowsocks address header is plain SOCKS5 framing
/// (`ATYP · ADDR · PORT`, atyp 1/3/4).
pub use crate::common::addr::{
    encode_socks5 as encode_address, encode_socks5_into as encode_address_into,
};

/// Pre-initialized cipher — avoids re-running key expansion on every encrypt/decrypt.
#[allow(clippy::large_enum_variant)]
enum CachedCipher {
    Aes128Gcm(Aes128Gcm),
    Aes192Gcm(Aes192Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20(ChaCha20Poly1305),
    XChaCha20(XChaCha20Poly1305),
}

/// Encrypt/decrypt dispatcher that works with any of the supported AEAD ciphers.
/// Cipher object is created once (key expansion) and reused for all operations.
pub(super) struct CipherCore {
    cached: CachedCipher,
}

/// XChaCha20-Poly1305 takes a 24-byte nonce. sing counts in a little-endian
/// nonce of the cipher's own size (`internal/shadowio/common.go`
/// increaseNonce), so the 12 counter bytes are its low half.
fn xnonce(nonce: &[u8; NONCE_LEN]) -> chacha20poly1305::XNonce {
    let mut xnonce = chacha20poly1305::XNonce::default();
    xnonce[..NONCE_LEN].copy_from_slice(nonce);
    xnonce
}

impl CipherCore {
    pub(super) fn new(cipher: AeadCipher, key: Vec<u8>) -> Self {
        let cached = match cipher {
            AeadCipher::Aes128Gcm | AeadCipher::Blake3Aes128Gcm => {
                CachedCipher::Aes128Gcm(Aes128Gcm::new(GenericArray::from_slice(&key)))
            }
            AeadCipher::Aes192Gcm => {
                CachedCipher::Aes192Gcm(Aes192Gcm::new(GenericArray::from_slice(&key)))
            }
            AeadCipher::Aes256Gcm | AeadCipher::Blake3Aes256Gcm => {
                CachedCipher::Aes256Gcm(Aes256Gcm::new(GenericArray::from_slice(&key)))
            }
            AeadCipher::ChaCha20Poly1305 | AeadCipher::Blake3ChaCha20Poly1305 => {
                CachedCipher::ChaCha20(ChaCha20Poly1305::new(GenericArray::from_slice(&key)))
            }
            AeadCipher::XChaCha20Poly1305 => {
                CachedCipher::XChaCha20(XChaCha20Poly1305::new(GenericArray::from_slice(&key)))
            }
        };
        Self { cached }
    }

    /// Encrypt `data` in-place using the given nonce, appending the AEAD tag.
    pub(super) fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        data: &mut Vec<u8>,
    ) -> Result<(), io::Error> {
        let nonce_ga = GenericArray::from_slice(nonce);
        match &self.cached {
            CachedCipher::Aes128Gcm(c) => c
                .encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| io::Error::other(format!("aes-128-gcm encrypt: {e}"))),
            CachedCipher::Aes192Gcm(c) => c
                .encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| io::Error::other(format!("aes-192-gcm encrypt: {e}"))),
            CachedCipher::Aes256Gcm(c) => c
                .encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| io::Error::other(format!("aes-256-gcm encrypt: {e}"))),
            CachedCipher::ChaCha20(c) => c
                .encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| io::Error::other(format!("chacha20-poly1305 encrypt: {e}"))),
            CachedCipher::XChaCha20(c) => c
                .encrypt_in_place(&xnonce(nonce), b"", data)
                .map_err(|e| io::Error::other(format!("xchacha20-poly1305 encrypt: {e}"))),
        }
    }

    /// Decrypt `data` in-place (data includes the appended AEAD tag).
    pub(super) fn decrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        data: &mut Vec<u8>,
    ) -> Result<(), io::Error> {
        let nonce_ga = GenericArray::from_slice(nonce);
        match &self.cached {
            CachedCipher::Aes128Gcm(c) => c.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("aes-128-gcm decrypt: {e}"),
                )
            }),
            CachedCipher::Aes192Gcm(c) => c.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("aes-192-gcm decrypt: {e}"),
                )
            }),
            CachedCipher::Aes256Gcm(c) => c.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("aes-256-gcm decrypt: {e}"),
                )
            }),
            CachedCipher::ChaCha20(c) => c.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("chacha20-poly1305 decrypt: {e}"),
                )
            }),
            CachedCipher::XChaCha20(c) => {
                c.decrypt_in_place(&xnonce(nonce), b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("xchacha20-poly1305 decrypt: {e}"),
                    )
                })
            }
        }
    }
}

/// Incrementing nonce counter (12 bytes, little-endian).
///
/// Starts at 0 and increments by 1 after each encrypt or decrypt operation.
struct NonceCounter {
    counter: [u8; NONCE_LEN],
}

impl NonceCounter {
    fn new() -> Self {
        Self {
            counter: [0u8; NONCE_LEN],
        }
    }

    fn current(&self) -> &[u8; NONCE_LEN] {
        &self.counter
    }

    fn increment(&mut self) {
        // Little-endian increment
        for byte in &mut self.counter {
            let (val, overflow) = byte.overflowing_add(1);
            *byte = val;
            if !overflow {
                break;
            }
        }
    }
}

enum WriteState {
    Ready,
    Flushing { buf: Vec<u8>, pos: usize },
}

/// Internal states for the read (decrypt) half.
enum ReadState {
    /// We need to read the salt from the remote server first.
    WaitingSalt { buf: Vec<u8> },
    /// SS2022 only: read and validate the fixed-size response header after salt.
    /// The response header is: [0x01][timestamp: 8 bytes][request_salt: key_len bytes]
    /// encrypted as a single AEAD chunk (header_len + TAG_LEN bytes on the wire).
    WaitingSs2022ResponseHeader { buf: Vec<u8>, header_len: usize },
    /// We need to read the encrypted length field (2 bytes + TAG_LEN).
    WaitingLength { buf: Vec<u8> },
    /// We need to read the encrypted payload (payload_len bytes + TAG_LEN).
    WaitingPayload { buf: Vec<u8>, payload_len: usize },
    /// We have decrypted data buffered and ready to hand out.
    Buffered { buf: Vec<u8>, pos: usize },
}

pin_project! {
    /// Shadowsocks AEAD encrypted stream.
    ///
    /// Wraps an inner async stream (TCP, TLS, WebSocket, etc.) and provides
    /// transparent AEAD encryption/decryption per the Shadowsocks protocol.
    ///
    /// Legacy wire format (client -> server):
    ///   [salt][encrypted_length(2) + tag(16)][encrypted_payload + tag(16)] ...
    ///   The first payload chunk contains the target address header.
    ///
    /// SS2022 wire format (client -> server):
    ///   [salt][encrypted_request_header + tag(16)][encrypted_length + tag][encrypted_payload + tag] ...
    ///   Request header: [0x00][timestamp_be(8)][variable_len_be(2)][socks_addr][padding_len(2)][padding][initial_data]
    ///
    /// SS2022 wire format (server -> client):
    ///   [salt][encrypted_response_header + tag(16)][encrypted_length + tag][encrypted_payload + tag] ...
    ///   Response header: [0x01][timestamp_be(8)][request_salt(key_len)][variable_length_be(2)][variable_data]
    pub struct SsStream<T> {
        #[pin]
        inner: T,
        cipher_type: AeadCipher,

        // SS2022 mode flag
        is_ss2022: bool,
        // The salt we sent in the request (needed to verify response header)
        request_salt: Vec<u8>,

        // The key session subkeys derive from, in both directions: the legacy
        // master key, or for SS2022 the last PSK of the `:`-separated list.
        session_key: Vec<u8>,

        // Encrypt state (write path)
        enc_cipher: Option<CipherCore>,
        enc_nonce: NonceCounter,
        write_state: WriteState,
        // Reusable buffers — avoids per-write heap allocations in the hot path.
        write_out_buf: Vec<u8>,
        write_payload_buf: Vec<u8>,

        // Decrypt state (read path)
        dec_cipher: Option<CipherCore>,
        dec_nonce: NonceCounter,
        read_state: ReadState,
        // Reusable buffer — avoids per-read Vec::new() allocation churn.
        read_reuse_buf: Vec<u8>,
    }
}

impl<T> SsStream<T> {
    /// Create a new SsStream wrapping the given inner stream.
    ///
    /// `key` is derived from the password via evp_bytes_to_key (legacy) or is the
    /// base64-decoded PSK (SS2022; the last one when several are configured).
    /// `cipher` specifies which AEAD cipher to use.
    /// `initial_payload` is the first data to send (typically the address header for legacy,
    /// or the SOCKS address header for SS2022).
    /// `identity_psks` are the SS2022 PSKs configured before `key`, outermost
    /// first; each adds an identity header to the request. Empty otherwise.
    ///
    /// The request is built here and stays pending until the first
    /// `poll_write`, which sends it even when called with an empty buffer —
    /// that is how the tunnel has the header leave at dial, like mihomo's
    /// `DialConn` (see `crate::proxy::Handshake`).
    pub fn new(
        inner: T,
        cipher: AeadCipher,
        key: Vec<u8>,
        initial_payload: Vec<u8>,
        identity_psks: &[Vec<u8>],
    ) -> Self {
        let is_ss2022 = cipher.is_ss2022();

        // Generate random salt for the encryption direction
        let salt = generate_salt(cipher.salt_len());

        // Derive the encryption subkey from session key + salt
        let enc_subkey = cipher.derive_subkey(&key, &salt);
        let enc_cipher = CipherCore::new(cipher, enc_subkey);

        // Keep a copy of the salt for SS2022 response header verification
        let request_salt = if is_ss2022 { salt.clone() } else { Vec::new() };

        // For SS2022: the request carries no payload (non-early mode),
        // matching mihomo's DialConn behavior. The address header + random padding
        // are sent as the initial AEAD chunks; user data follows via standard chunks.
        // For legacy: build the initial buffer immediately.
        let (write_state, enc_nonce) = if is_ss2022 {
            let mut nonce = NonceCounter::new();
            let buf = build_ss2022_request_buffer(
                &salt,
                &enc_cipher,
                &mut nonce,
                &initial_payload,
                identity_psks,
                &key,
                &[], // No early payload — send addr+padding only (like mihomo DialConn)
            );
            (WriteState::Flushing { buf, pos: 0 }, nonce)
        } else {
            let mut nonce = NonceCounter::new();
            let buf = build_initial_buffer(&salt, &enc_cipher, &mut nonce, &initial_payload);
            (WriteState::Flushing { buf, pos: 0 }, nonce)
        };

        // Lazy buffer allocation — grow on first use, reuse after.
        Self {
            inner,
            cipher_type: cipher,
            is_ss2022,
            request_salt,
            session_key: key,
            enc_cipher: Some(enc_cipher),
            enc_nonce,
            write_state,
            write_out_buf: Vec::new(),
            write_payload_buf: Vec::new(),
            dec_cipher: None,
            dec_nonce: NonceCounter::new(),
            read_state: ReadState::WaitingSalt { buf: Vec::new() },
            read_reuse_buf: Vec::new(),
        }
    }
}

/// Build the initial send buffer: [salt][encrypted chunks of initial_payload].
fn build_initial_buffer(
    salt: &[u8],
    cipher: &CipherCore,
    nonce: &mut NonceCounter,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(salt.len() + payload.len() + 256);
    buf.extend_from_slice(salt);

    // Split payload into chunks of MAX_PAYLOAD_SIZE and encrypt each
    let mut offset = 0;
    while offset < payload.len() {
        let chunk_len = std::cmp::min(MAX_PAYLOAD_SIZE, payload.len() - offset);
        let chunk = &payload[offset..offset + chunk_len];

        // Encrypt length (2 bytes big-endian)
        let mut len_buf = Vec::from([(chunk_len >> 8) as u8, (chunk_len & 0xFF) as u8]);
        cipher
            .encrypt_in_place(nonce.current(), &mut len_buf)
            .expect("encrypt length");
        nonce.increment();
        buf.extend_from_slice(&len_buf);

        // Encrypt payload
        let mut payload_buf = chunk.to_vec();
        cipher
            .encrypt_in_place(nonce.current(), &mut payload_buf)
            .expect("encrypt payload");
        nonce.increment();
        buf.extend_from_slice(&payload_buf);

        offset += chunk_len;
    }

    buf
}

/// Build the initial send buffer for SS2022:
/// [salt][identity_headers (16 bytes per identity PSK)][encrypted_request_header + tag(16)]
///
/// The request header plaintext is:
///   [0x00 (client type)][timestamp_be(8)][variable_length_be(2)][socks_addr][padding_len_be(2)][padding][initial_data]
///
/// The entire header is encrypted as ONE AEAD chunk (nonce=0).
/// After the header, subsequent data uses standard length-prefixed chunks (nonce continues).
///
/// `identity_psks` and `psk` are the configured key list (see
/// [`build_identity_headers`]); the session cipher (passed in `cipher`) must
/// already be derived from `psk`.
fn build_ss2022_request_buffer(
    salt: &[u8],
    cipher: &CipherCore,
    nonce: &mut NonceCounter,
    addr_header: &[u8],
    identity_psks: &[Vec<u8>],
    psk: &[u8],
    first_data: &[u8],
) -> Vec<u8> {
    // SS2022 TCP request format (per shadowsocks-rust / SIP022):
    //
    //   [salt][EIH?][AEAD_header (nonce=0)][AEAD_data (nonce=1)]
    //
    // AEAD_header plaintext (11 bytes):
    //   [type(1)=0x00][timestamp(8)][data_length(2)]
    //   data_length = length of the NEXT chunk's plaintext (addr+padding_len+padding)
    //
    // AEAD_data plaintext:
    //   [socks_addr][padding_len(2)][padding bytes]
    //
    // Only 2 nonces used. No separate encrypted length prefixes — the header
    // chunk embeds the data length. After this, subsequent writes use the
    // standard [enc_len(18)][enc_payload] format with nonces 2, 3, 4, ...

    let timestamp = unix_now();

    // Data chunk plaintext: [socks_addr][padding_len(2)][padding][first_user_data]
    // When first_data is non-empty, padding=0. When empty, random 1-900 padding.
    let padding_size: u16 = if first_data.is_empty() {
        use rand::Rng;
        rand::thread_rng().gen_range(1..=900)
    } else {
        0
    };
    let mut data_payload =
        Vec::with_capacity(addr_header.len() + 2 + padding_size as usize + first_data.len());
    data_payload.extend_from_slice(addr_header);
    data_payload.extend_from_slice(&padding_size.to_be_bytes());
    if padding_size > 0 {
        data_payload.resize(data_payload.len() + padding_size as usize, 0);
    }
    data_payload.extend_from_slice(first_data);

    // Header chunk plaintext (11 bytes): [type][timestamp][data_length]
    let mut header = Vec::with_capacity(11);
    header.push(0x00); // type: client request
    header.extend_from_slice(&timestamp.to_be_bytes()); // 8 bytes
    header.extend_from_slice(&(data_payload.len() as u16).to_be_bytes()); // 2 bytes

    tracing::debug!(
        "SS2022 request: timestamp={} data_len={} salt_len={} identity={}",
        timestamp,
        data_payload.len(),
        salt.len(),
        !identity_psks.is_empty(),
    );

    let identity_headers = build_identity_headers(identity_psks, psk, salt);
    let mut buf = Vec::with_capacity(
        salt.len()
            + identity_headers.len()
            + (header.len() + TAG_LEN)
            + (data_payload.len() + TAG_LEN),
    );

    // [1] Salt (plaintext)
    buf.extend_from_slice(salt);

    // [2] EIH (identity headers, AES-ECB encrypted, multi-user only)
    buf.extend_from_slice(&identity_headers);

    // [3] AEAD header chunk (nonce=0): 11 bytes plaintext → 27 bytes on wire
    cipher
        .encrypt_in_place(nonce.current(), &mut header)
        .expect("encrypt ss2022 header");
    nonce.increment();
    buf.extend_from_slice(&header);

    // [4] AEAD data chunk (nonce=1): data_payload bytes → data_payload.len()+16 on wire
    cipher
        .encrypt_in_place(nonce.current(), &mut data_payload)
        .expect("encrypt ss2022 data");
    nonce.increment();
    buf.extend_from_slice(&data_payload);

    tracing::debug!(
        "SS2022 wire: total={} (salt={} eih={} header={} data={})",
        buf.len(),
        salt.len(),
        identity_headers.len(),
        header.len(),
        data_payload.len(),
    );

    buf
}

/// AES single-block (ECB) cipher keyed by an SS2022 PSK or identity subkey.
/// The key is 16 or 32 bytes — the `keySaltLength` of the two AES methods,
/// the only ones with identity headers and an encrypted UDP packet header.
#[allow(clippy::large_enum_variant)]
pub(super) enum AesBlock {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

impl AesBlock {
    pub(super) fn new(key: &[u8]) -> Self {
        if key.len() == 16 {
            Self::Aes128(aes::Aes128::new(GenericArray::from_slice(key)))
        } else {
            Self::Aes256(aes::Aes256::new(GenericArray::from_slice(key)))
        }
    }

    pub(super) fn encrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Aes128(aes) => aes.encrypt_block(block),
            Self::Aes256(aes) => aes.encrypt_block(block),
        }
    }

    pub(super) fn decrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Aes128(aes) => aes.decrypt_block(block),
            Self::Aes256(aes) => aes.decrypt_block(block),
        }
    }
}

/// What an identity header says about the next PSK: the first 16 bytes of its
/// BLAKE3 hash (`shadowaead_2022/method.go` NewMethod `pskHash`).
pub(super) fn psk_hash(psk: &[u8]) -> [u8; 16] {
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&blake3::hash(psk).as_bytes()[..16]);
    hash
}

/// Build the SS2022 identity headers of a TCP request: one 16-byte block per
/// identity PSK, each naming the PSK that follows it in the configured list
/// (`identity_psks`, then `psk`).
///
/// mihomo compat: `shadowaead_2022/method.go` writeExtendedIdentityHeaders.
/// For each identity PSK:
/// 1. identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", identity_psk || salt)
/// 2. AES-ECB encrypt the next PSK's hash with identity_subkey
fn build_identity_headers(identity_psks: &[Vec<u8>], psk: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut headers = Vec::with_capacity(identity_psks.len() * 16);
    for (i, identity_psk) in identity_psks.iter().enumerate() {
        let mut identity_subkey = vec![0u8; identity_psk.len()];
        let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
        hasher.update(identity_psk);
        hasher.update(salt);
        hasher.finalize_xof().fill(&mut identity_subkey);

        let next_psk = identity_psks.get(i + 1).map_or(psk, Vec::as_slice);
        let mut block = psk_hash(next_psk);
        AesBlock::new(&identity_subkey).encrypt(&mut block);
        headers.extend_from_slice(&block);
    }
    headers
}

/// Seconds since the Unix epoch, as SS2022 timestamps count them.
///
/// mihomo compat: `MethodOptions{TimeFunc: ntp.Now}` (shadowsocks.go).
pub(super) fn unix_now() -> u64 {
    // A badly-set clock (before epoch) yields 0, which simply fails the
    // timestamp checks instead of panicking.
    crate::ntp::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a random salt of the given length.
pub(super) fn generate_salt(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Standalone AEAD encrypt for UDP packets (each packet uses a fresh key/nonce).
pub(super) fn encrypt_in_place_standalone(
    cipher: &AeadCipher,
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    data: &mut Vec<u8>,
) -> anyhow::Result<()> {
    Ok(CipherCore::new(*cipher, key.to_vec()).encrypt_in_place(nonce, data)?)
}

/// Standalone AEAD decrypt for UDP packets (each packet uses a fresh key/nonce).
pub(super) fn decrypt_in_place_standalone(
    cipher: &AeadCipher,
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    data: &mut Vec<u8>,
) -> anyhow::Result<()> {
    Ok(CipherCore::new(*cipher, key.to_vec()).decrypt_in_place(nonce, data)?)
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for SsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut me = self.project();

        loop {
            match me.read_state {
                ReadState::WaitingSalt {
                    buf: ref mut salt_buf,
                } => {
                    let salt_len = me.cipher_type.salt_len();
                    // Read salt bytes from inner stream
                    while salt_buf.len() < salt_len {
                        let mut tmp = [0u8; 64];
                        let remaining = salt_len - salt_buf.len();
                        let to_read = std::cmp::min(remaining, tmp.len());
                        let mut read_buf = ReadBuf::new(&mut tmp[..to_read]);
                        match me.inner.as_mut().poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading salt",
                                    )));
                                }
                                salt_buf.extend_from_slice(read_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Derive decryption subkey from session key + received salt
                    // For multi-user, session_key is the user_key; for single-user, it's master_key.
                    let dec_subkey = me.cipher_type.derive_subkey(me.session_key, salt_buf);
                    *me.dec_cipher = Some(CipherCore::new(*me.cipher_type, dec_subkey));

                    if *me.is_ss2022 {
                        // SS2022 response format (per shadowsocks-rust):
                        //   [salt][AEAD_header (nonce=0)][AEAD_data (nonce=1)][standard chunks...]
                        //
                        // Header plaintext: [type(1)=0x01][timestamp(8)][request_salt(key_len)][data_length(2)]
                        // The header is a fixed-size AEAD chunk (no length prefix).
                        let header_plaintext_len = 1 + 8 + me.cipher_type.salt_len() + 2;
                        *me.read_state = ReadState::WaitingSs2022ResponseHeader {
                            buf: Vec::new(),
                            header_len: header_plaintext_len,
                        };
                    } else {
                        // Legacy: transition to reading length-prefixed chunks
                        *me.read_state = ReadState::WaitingLength { buf: Vec::new() };
                    }
                }

                ReadState::WaitingSs2022ResponseHeader {
                    buf: ref mut hdr_buf,
                    header_len,
                } => {
                    // SS2022 response: [salt][AEAD_header(nonce=0)][AEAD_data(nonce=1)][std chunks...]
                    // Header is a fixed-size AEAD block (header_len + TAG_LEN bytes, no length prefix).
                    // Header plaintext: [type(1)][timestamp(8)][request_salt(key_len)][data_length(2)]

                    let need = *header_len + TAG_LEN;
                    while hdr_buf.len() < need {
                        let mut tmp = [0u8; 128];
                        let remaining = need - hdr_buf.len();
                        let to_read = std::cmp::min(remaining, tmp.len());
                        let mut read_buf = ReadBuf::new(&mut tmp[..to_read]);
                        match me.inner.as_mut().poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed reading SS2022 response header",
                                    )));
                                }
                                hdr_buf.extend_from_slice(read_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Decrypt header (nonce=0)
                    let dec = me
                        .dec_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("decryption cipher not initialized"))?;
                    dec.decrypt_in_place(me.dec_nonce.current(), hdr_buf)?;
                    me.dec_nonce.increment();

                    // Validate type byte
                    if hdr_buf.is_empty() || hdr_buf[0] != 0x01 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ss2022: invalid response header type (expected 0x01)",
                        )));
                    }

                    // Validate timestamp (bytes 1..9)
                    let resp_ts = u64::from_be_bytes(
                        hdr_buf[1..9].try_into().expect("8 bytes for timestamp"),
                    );
                    let now_ts = unix_now();
                    let ts_diff = now_ts.abs_diff(resp_ts);
                    if ts_diff > 30 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("ss2022: response timestamp too far off (diff={ts_diff}s)"),
                        )));
                    }

                    // Validate request salt echo (bytes 9..9+key_len)
                    let salt_len = me.cipher_type.salt_len();
                    let echoed_salt = &hdr_buf[9..9 + salt_len];
                    if echoed_salt != me.request_salt.as_slice() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ss2022: response header request salt mismatch",
                        )));
                    }

                    // Read data_length from header (bytes 9+key_len..9+key_len+2)
                    let dl_offset = 9 + salt_len;
                    let data_length =
                        u16::from_be_bytes([hdr_buf[dl_offset], hdr_buf[dl_offset + 1]]) as usize;

                    // Now read the AEAD data chunk (nonce=1): data_length + TAG_LEN bytes.
                    // This chunk contains the server's initial response payload.
                    // After this, standard length-prefixed chunks start at nonce=2.
                    // mihomo compat: readResponse reads this chunk whatever its
                    // length (`reader.ReadFixedBuffer(int(length))`) — an empty
                    // one is still 16 bytes of tag under nonce 1.
                    *me.read_state = ReadState::WaitingPayload {
                        buf: Vec::new(),
                        payload_len: data_length,
                    };
                }

                ReadState::WaitingLength {
                    buf: ref mut len_buf,
                } => {
                    let need = 2 + TAG_LEN; // 2 bytes length + 16 bytes tag
                    while len_buf.len() < need {
                        let mut tmp = [0u8; 32];
                        let remaining = need - len_buf.len();
                        let to_read = std::cmp::min(remaining, tmp.len());
                        let mut read_buf = ReadBuf::new(&mut tmp[..to_read]);
                        match me.inner.as_mut().poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    if len_buf.is_empty() {
                                        // Clean EOF - no more data
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading length",
                                    )));
                                }
                                len_buf.extend_from_slice(read_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Decrypt the length field
                    let dec = me
                        .dec_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("decryption cipher not initialized"))?;
                    dec.decrypt_in_place(me.dec_nonce.current(), len_buf)?;
                    me.dec_nonce.increment();

                    // Parse the 2-byte big-endian length. mihomo compat: any
                    // length is accepted (`internal/shadowio/reader.go`
                    // readBuffer) — the chunk size caps bind the writer only.
                    let payload_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);

                    // Reuse the read buffer instead of allocating a new Vec
                    me.read_reuse_buf.clear();
                    *me.read_state = ReadState::WaitingPayload {
                        buf: std::mem::take(me.read_reuse_buf),
                        payload_len,
                    };
                }

                ReadState::WaitingPayload {
                    buf: ref mut payload_buf,
                    payload_len,
                } => {
                    let need = *payload_len + TAG_LEN;
                    while payload_buf.len() < need {
                        let mut tmp = [0u8; 4096];
                        let remaining = need - payload_buf.len();
                        let to_read = std::cmp::min(remaining, tmp.len());
                        let mut read_buf = ReadBuf::new(&mut tmp[..to_read]);
                        match me.inner.as_mut().poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "connection closed while reading payload",
                                    )));
                                }
                                payload_buf.extend_from_slice(read_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    // Decrypt payload
                    let dec = me
                        .dec_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("decryption cipher not initialized"))?;
                    dec.decrypt_in_place(me.dec_nonce.current(), payload_buf)?;
                    me.dec_nonce.increment();

                    let decrypted = std::mem::take(payload_buf);
                    *me.read_state = ReadState::Buffered {
                        buf: decrypted,
                        pos: 0,
                    };
                }

                ReadState::Buffered {
                    buf: ref dec_buf,
                    ref mut pos,
                } => {
                    let remaining = &dec_buf[*pos..];
                    if remaining.is_empty() {
                        // Reclaim buffer for reuse instead of dropping + allocating
                        if let ReadState::Buffered { buf, .. } = std::mem::replace(
                            me.read_state,
                            ReadState::WaitingLength { buf: Vec::new() },
                        ) {
                            *me.read_reuse_buf = buf;
                        }
                        // Set up WaitingLength with a small reused buffer
                        // (the main read_reuse_buf is reserved for the larger payload)
                        continue;
                    }

                    let to_copy = std::cmp::min(remaining.len(), buf.remaining());
                    buf.put_slice(&remaining[..to_copy]);
                    *pos += to_copy;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for SsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut me = self.project();

        // Flush any pending data
        while let WriteState::Flushing {
            ref buf,
            ref mut pos,
        } = me.write_state
        {
            if *pos < buf.len() {
                match me.inner.as_mut().poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero",
                            )));
                        }
                        *pos += n;
                        if *pos < buf.len() {
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Reclaim the flushed buffer for reuse instead of dropping it
            if let WriteState::Flushing { buf, .. } =
                std::mem::replace(me.write_state, WriteState::Ready)
            {
                *me.write_out_buf = buf;
            }
        }

        // Now encrypt the new data
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let enc = me
            .enc_cipher
            .as_ref()
            .ok_or_else(|| io::Error::other("encryption cipher not initialized"))?;

        // Take at most MAX_PAYLOAD_SIZE bytes (SS2022 allows larger chunks)
        let max_size = if *me.is_ss2022 {
            MAX_PAYLOAD_SIZE_2022
        } else {
            MAX_PAYLOAD_SIZE
        };
        let chunk_len = std::cmp::min(max_size, data.len());
        let chunk = &data[..chunk_len];

        // Reuse pre-allocated buffers instead of allocating new Vecs per write.
        // Encrypt length (2 bytes -> 2 + TAG_LEN after encryption)
        me.write_out_buf.clear();
        me.write_out_buf.push((chunk_len >> 8) as u8);
        me.write_out_buf.push((chunk_len & 0xFF) as u8);
        enc.encrypt_in_place(me.enc_nonce.current(), me.write_out_buf)?;
        me.enc_nonce.increment();

        // Encrypt payload using reusable buffer
        me.write_payload_buf.clear();
        me.write_payload_buf.extend_from_slice(chunk);
        enc.encrypt_in_place(me.enc_nonce.current(), me.write_payload_buf)?;
        me.enc_nonce.increment();

        // Build the output: [encrypted_len + tag][encrypted_payload + tag]
        // Swap out_buf and write_out_buf so out_buf has len prefix, then append payload
        let out_len = me.write_out_buf.len() + me.write_payload_buf.len();
        let mut out = std::mem::take(me.write_out_buf);
        out.reserve(out_len - out.len());
        out.extend_from_slice(me.write_payload_buf);

        // Write the encrypted chunk. Try to write all of it in a loop.
        // If the inner stream can't accept all data, buffer the remainder
        // in Flushing state (will be flushed on next poll_write or poll_flush).
        let mut pos = 0;
        while pos < out.len() {
            match me.inner.as_mut().poll_write(cx, &out[pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )));
                    }
                    pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    *me.write_state = WriteState::Flushing { buf: out, pos };
                    return Poll::Ready(Ok(chunk_len));
                }
            }
        }
        // Write completed fully — reclaim the buffer for reuse
        *me.write_out_buf = out;
        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut me = self.project();

        // Flush pending encrypted data first
        if let WriteState::Flushing {
            ref buf,
            ref mut pos,
        } = me.write_state
        {
            while *pos < buf.len() {
                match me.inner.as_mut().poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero during flush",
                            )));
                        }
                        *pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        // Reclaim the flushed buffer for reuse
        if let WriteState::Flushing { buf, .. } =
            std::mem::replace(me.write_state, WriteState::Ready)
        {
            *me.write_out_buf = buf;
        } else {
            *me.write_state = WriteState::Ready;
        }

        me.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut me = self.project();

        // Flush pending data before shutdown
        if let WriteState::Flushing {
            ref buf,
            ref mut pos,
        } = me.write_state
        {
            while *pos < buf.len() {
                match me.inner.as_mut().poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            break;
                        }
                        *pos += n;
                    }
                    Poll::Ready(Err(_)) => break,
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        *me.write_state = WriteState::Ready;

        me.inner.as_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{legacy_subkey, read_request_2022, response_2022, StreamKey};
    use super::*;
    use crate::common::addr::Address;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    #[test]
    fn evp_bytes_to_key_16() {
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(key.len(), 16);
        // MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        assert_eq!(hex::encode(&key), "5f4dcc3b5aa765d61d8327deb882cf99");
    }

    #[test]
    fn evp_bytes_to_key_32() {
        let key = evp_bytes_to_key(b"password", 32);
        assert_eq!(key.len(), 32);
        // First 16 bytes should be MD5("password")
        assert_eq!(hex::encode(&key[..16]), "5f4dcc3b5aa765d61d8327deb882cf99");
    }

    #[test]
    fn evp_bytes_to_key_different_passwords() {
        let key1 = evp_bytes_to_key(b"alpha", 32);
        let key2 = evp_bytes_to_key(b"bravo", 32);
        assert_ne!(key1, key2);
    }

    #[test]
    fn encode_address_ipv4() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443));
        let addr = Address::Ip(sock);
        let encoded = encode_address(&addr);
        // addr_type(1) + ipv4(4) + port(2) = 7 bytes
        assert_eq!(encoded.len(), 7);
        assert_eq!(encoded[0], 0x01); // IPv4 type
        assert_eq!(&encoded[1..5], &[1, 2, 3, 4]);
        assert_eq!(&encoded[5..7], &443u16.to_be_bytes());
    }

    #[test]
    fn encode_address_ipv6() {
        let sock = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0));
        let addr = Address::Ip(sock);
        let encoded = encode_address(&addr);
        // addr_type(1) + ipv6(16) + port(2) = 19 bytes
        assert_eq!(encoded.len(), 19);
        assert_eq!(encoded[0], 0x04); // IPv6 type
        assert_eq!(&encoded[17..19], &80u16.to_be_bytes());
    }

    #[test]
    fn encode_address_domain() {
        let addr = Address::Domain("example.com".to_string(), 8080);
        let encoded = encode_address(&addr);
        // addr_type(1) + len(1) + domain(11) + port(2) = 15 bytes
        assert_eq!(encoded.len(), 15);
        assert_eq!(encoded[0], 0x03); // Domain type
        assert_eq!(encoded[1], 11); // "example.com".len()
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &8080u16.to_be_bytes());
    }

    #[test]
    fn nonce_increment() {
        let mut nonce = NonceCounter::new();
        assert_eq!(nonce.current(), &[0u8; 12]);

        nonce.increment();
        let mut expected = [0u8; 12];
        expected[0] = 1;
        assert_eq!(nonce.current(), &expected);

        // Increment 255 more times to get to 256 (0x100)
        for _ in 0..255 {
            nonce.increment();
        }
        let mut expected256 = [0u8; 12];
        expected256[0] = 0;
        expected256[1] = 1; // little-endian: 256 = 0x00, 0x01
        assert_eq!(nonce.current(), &expected256);
    }

    #[test]
    fn nonce_increment_overflow_byte() {
        let mut nonce = NonceCounter::new();
        // Set first byte to 0xFF
        nonce.counter[0] = 0xFF;
        nonce.increment();
        // Should carry over to second byte
        assert_eq!(nonce.counter[0], 0x00);
        assert_eq!(nonce.counter[1], 0x01);
    }

    #[test]
    fn cipher_from_name() {
        assert_eq!(
            AeadCipher::from_name("aes-128-gcm"),
            Some(AeadCipher::Aes128Gcm)
        );
        assert_eq!(
            AeadCipher::from_name("aes-256-gcm"),
            Some(AeadCipher::Aes256Gcm)
        );
        assert_eq!(
            AeadCipher::from_name("chacha20-ietf-poly1305"),
            Some(AeadCipher::ChaCha20Poly1305)
        );
        assert_eq!(
            AeadCipher::from_name("chacha20-poly1305"),
            Some(AeadCipher::ChaCha20Poly1305)
        );
        assert_eq!(
            AeadCipher::from_name("aes-192-gcm"),
            Some(AeadCipher::Aes192Gcm)
        );
        assert_eq!(
            AeadCipher::from_name("xchacha20-ietf-poly1305"),
            Some(AeadCipher::XChaCha20Poly1305)
        );
        assert_eq!(AeadCipher::from_name("unknown"), None);
    }

    #[test]
    fn cipher_key_lengths() {
        assert_eq!(AeadCipher::Aes128Gcm.key_len(), 16);
        assert_eq!(AeadCipher::Aes192Gcm.key_len(), 24);
        assert_eq!(AeadCipher::Aes256Gcm.key_len(), 32);
        assert_eq!(AeadCipher::ChaCha20Poly1305.key_len(), 32);
        assert_eq!(AeadCipher::XChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    fn ss2022_cipher_detection() {
        assert!(!AeadCipher::Aes128Gcm.is_ss2022());
        assert!(!AeadCipher::Aes256Gcm.is_ss2022());
        assert!(!AeadCipher::ChaCha20Poly1305.is_ss2022());
        assert!(AeadCipher::Blake3Aes128Gcm.is_ss2022());
        assert!(AeadCipher::Blake3Aes256Gcm.is_ss2022());
        assert!(AeadCipher::Blake3ChaCha20Poly1305.is_ss2022());
    }

    #[test]
    fn ss2022_blake3_key_derivation() {
        let cipher = AeadCipher::Blake3Aes256Gcm;
        let key = vec![0x42u8; 32];
        let salt = vec![0xABu8; 32];
        let subkey = cipher.derive_subkey(&key, &salt);
        assert_eq!(subkey.len(), 32);

        // Same inputs should produce same output
        let subkey2 = cipher.derive_subkey(&key, &salt);
        assert_eq!(subkey, subkey2);

        // Different salt should produce different subkey
        let salt2 = vec![0xCDu8; 32];
        let subkey3 = cipher.derive_subkey(&key, &salt2);
        assert_ne!(subkey, subkey3);
    }

    #[test]
    fn ss2022_request_buffer_structure_aes256() {
        let cipher = AeadCipher::Blake3Aes256Gcm;
        let key = vec![0x42u8; 32];
        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&key, &salt);
        let enc_cipher = CipherCore::new(cipher, subkey.clone());
        let mut nonce = NonceCounter::new();

        // Address header for example.com:443
        let addr = Address::Domain("example.com".to_string(), 443);
        let addr_header = encode_address(&addr);

        let buf = build_ss2022_request_buffer(
            &salt,
            &enc_cipher,
            &mut nonce,
            &addr_header,
            &[],
            &key,
            b"",
        );

        // Buffer should start with the salt
        assert_eq!(&buf[..32], &salt[..]);

        // SS2022 format: [salt(32)][AEAD_header(11+16=27)][AEAD_data(variable+16)]
        // Data includes random padding when no first_data, so size varies
        let header_enc_len = 11 + TAG_LEN; // 27
        assert!(buf.len() >= 32 + header_enc_len + TAG_LEN);

        // Verify we can decrypt the header chunk (nonce=0)
        let dec_cipher = CipherCore::new(cipher, subkey);
        let mut dec_nonce = NonceCounter::new();
        let mut header_data = buf[32..32 + header_enc_len].to_vec();
        dec_cipher
            .decrypt_in_place(dec_nonce.current(), &mut header_data)
            .expect("decrypt ss2022 header");
        dec_nonce.increment();

        assert_eq!(header_data[0], 0x00); // client type
        let ts = u64::from_be_bytes(header_data[1..9].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(ts.abs_diff(now) < 5);

        let data_len = u16::from_be_bytes(header_data[9..11].try_into().unwrap()) as usize;
        // data_len >= addr + padding_len(2) + padding(0-900)
        assert!(data_len >= addr_header.len() + 2);

        // Verify data chunk (nonce=1)
        let mut data_data = buf[32 + header_enc_len..].to_vec();
        dec_cipher
            .decrypt_in_place(dec_nonce.current(), &mut data_data)
            .expect("decrypt ss2022 data");
        assert_eq!(&data_data[..addr_header.len()], &addr_header[..]);

        // Nonce should be 2 (header + data)
        assert_eq!(nonce.current()[0], 2);
    }

    #[test]
    fn ss2022_request_buffer_structure_aes128() {
        let cipher = AeadCipher::Blake3Aes128Gcm;
        let key = vec![0x42u8; 16];
        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&key, &salt);
        let enc_cipher = CipherCore::new(cipher, subkey.clone());
        let mut nonce = NonceCounter::new();

        let addr = Address::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            443,
        )));
        let addr_header = encode_address(&addr);

        let buf = build_ss2022_request_buffer(
            &salt,
            &enc_cipher,
            &mut nonce,
            &addr_header,
            &[],
            &key,
            b"",
        );

        // Salt is 16 bytes for AES-128
        assert_eq!(&buf[..16], &salt[..]);

        // Verify header chunk decryption (nonce=0)
        let dec_cipher = CipherCore::new(cipher, subkey);
        let dec_nonce = NonceCounter::new();
        let header_enc_len = 11 + TAG_LEN;
        let mut header_data = buf[16..16 + header_enc_len].to_vec();
        dec_cipher
            .decrypt_in_place(dec_nonce.current(), &mut header_data)
            .expect("decrypt ss2022 header");

        assert_eq!(header_data[0], 0x00); // client type
    }

    #[test]
    fn ss2022_legacy_buffer_uses_length_prefixed_chunks() {
        let cipher = AeadCipher::Aes256Gcm;
        let key = evp_bytes_to_key(b"testpassword", cipher.key_len());
        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&key, &salt);
        let enc_cipher = CipherCore::new(cipher, subkey.clone());
        let mut nonce = NonceCounter::new();

        let payload = b"Hello, World!";
        let buf = build_initial_buffer(&salt, &enc_cipher, &mut nonce, payload);

        // Buffer: salt(32) + enc_length(2+16) + enc_payload(13+16) = 32 + 18 + 29 = 79
        assert_eq!(buf.len(), 32 + (2 + TAG_LEN) + (payload.len() + TAG_LEN));

        // Verify we can decrypt the legacy format
        let dec_cipher = CipherCore::new(cipher, subkey);
        let mut dec_nonce = NonceCounter::new();

        // Decrypt length
        let mut len_data = buf[32..32 + 2 + TAG_LEN].to_vec();
        dec_cipher
            .decrypt_in_place(dec_nonce.current(), &mut len_data)
            .expect("decrypt legacy length");
        dec_nonce.increment();

        let payload_len = ((len_data[0] as usize) << 8) | (len_data[1] as usize);
        assert_eq!(payload_len, payload.len());

        // Decrypt payload
        let payload_start = 32 + 2 + TAG_LEN;
        let mut payload_data = buf[payload_start..].to_vec();
        dec_cipher
            .decrypt_in_place(dec_nonce.current(), &mut payload_data)
            .expect("decrypt legacy payload");

        assert_eq!(&payload_data, payload);
    }

    #[tokio::test]
    async fn ss2022_stream_roundtrip_write_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cipher = AeadCipher::Blake3Aes256Gcm;
        let key = vec![0x42u8; 32];
        let addr = Address::Domain("example.com".to_string(), 443);
        let addr_header = encode_address(&addr);

        // Create a duplex (in-memory) stream pair
        let (client_io, server_io) = tokio::io::duplex(16384);

        // Create the client SsStream (writes SS2022 request)
        let mut client = SsStream::new(client_io, cipher, key.clone(), addr_header.clone(), &[]);

        // Write some data through the client
        let test_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(test_data).await.expect("write test data");
        client.flush().await.expect("flush");

        // Now simulate reading on the server side:
        // The server would see: [salt][encrypted_header+tag][enc_len+tag][enc_payload+tag]
        // We verify the wire format is correct by reading raw bytes
        let mut server_reader = tokio::io::BufReader::new(server_io);
        let mut raw = Vec::new();
        // Read what's available (non-blocking won't work, use timeout)
        let read_task = tokio::time::timeout(std::time::Duration::from_millis(100), async {
            let mut buf = [0u8; 8192];
            let n = server_reader.read(&mut buf).await.unwrap();
            raw.extend_from_slice(&buf[..n]);
            // Try to read more
            match tokio::time::timeout(
                std::time::Duration::from_millis(50),
                server_reader.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => raw.extend_from_slice(&buf[..n]),
                _ => {}
            }
        });
        read_task.await.ok();

        // Verify: starts with 32-byte salt
        assert!(raw.len() >= 32, "raw data too short: {} bytes", raw.len());

        let salt = &raw[..32];

        // Derive subkey and decrypt
        let subkey = cipher.derive_subkey(&key, salt);
        let dec = CipherCore::new(cipher, subkey);
        let mut nonce = NonceCounter::new();

        // Non-early mode: [salt(32)][AEAD_header(27)][AEAD_data(addr+padding+TAG)]
        // Then separately: [enc_len(18)][enc_payload(test_data+TAG)]
        let header_enc_len = 11 + TAG_LEN;

        // Decrypt header chunk (nonce=0)
        let mut header_data = raw[32..32 + header_enc_len].to_vec();
        dec.decrypt_in_place(nonce.current(), &mut header_data)
            .expect("decrypt ss2022 header from wire");
        nonce.increment();

        assert_eq!(header_data[0], 0x00); // type

        // Decrypt data chunk (nonce=1) — contains addr + padding_len + padding (no payload)
        let data_len = u16::from_be_bytes(header_data[9..11].try_into().unwrap()) as usize;
        let data_start = 32 + header_enc_len;
        let data_enc_end = data_start + data_len + TAG_LEN;
        let mut data_chunk = raw[data_start..data_enc_end].to_vec();
        dec.decrypt_in_place(nonce.current(), &mut data_chunk)
            .expect("decrypt ss2022 data from wire");
        nonce.increment();

        assert_eq!(&data_chunk[..addr_header.len()], &addr_header[..]);

        // Then test_data follows as standard encrypted chunks (nonce=2,3)
        let chunk_start = data_enc_end;
        if raw.len() > chunk_start {
            // Decrypt length (nonce=2)
            let mut len_buf = raw[chunk_start..chunk_start + 2 + TAG_LEN].to_vec();
            dec.decrypt_in_place(nonce.current(), &mut len_buf)
                .expect("decrypt length chunk");
            nonce.increment();
            let payload_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;

            // Decrypt payload (nonce=3)
            let pl_start = chunk_start + 2 + TAG_LEN;
            let mut payload_buf = raw[pl_start..pl_start + payload_len + TAG_LEN].to_vec();
            dec.decrypt_in_place(nonce.current(), &mut payload_buf)
                .expect("decrypt payload chunk");

            assert_eq!(&payload_buf[..], test_data);
        }
    }

    #[test]
    fn ss2022_nonce_increments_correctly_after_header() {
        // After building the SS2022 request buffer, nonce should be at 1
        // (one increment for the header encryption).
        // Subsequent writes should continue from nonce 1.
        let cipher = AeadCipher::Blake3Aes256Gcm;
        let key = vec![0x42u8; 32];
        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&key, &salt);
        let enc_cipher = CipherCore::new(cipher, subkey);
        let mut nonce = NonceCounter::new();

        let addr = Address::Domain("test.com".to_string(), 80);
        let addr_header = encode_address(&addr);

        let _ = build_ss2022_request_buffer(
            &salt,
            &enc_cipher,
            &mut nonce,
            &addr_header,
            &[],
            &key,
            b"",
        );

        // After building the SS2022 request, nonce should be 2 (header + data)
        let mut expected = [0u8; NONCE_LEN];
        expected[0] = 2;
        assert_eq!(nonce.current(), &expected);
    }

    #[test]
    fn legacy_nonce_increments_twice_per_chunk() {
        // Legacy format: each chunk uses 2 nonce values (one for length, one for payload)
        let cipher = AeadCipher::Aes256Gcm;
        let key = evp_bytes_to_key(b"pass", cipher.key_len());
        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&key, &salt);
        let enc_cipher = CipherCore::new(cipher, subkey);
        let mut nonce = NonceCounter::new();

        let payload = b"test data";
        let _ = build_initial_buffer(&salt, &enc_cipher, &mut nonce, payload);

        // After one chunk, nonce should be 2 (one for length, one for payload)
        let mut expected = [0u8; NONCE_LEN];
        expected[0] = 2;
        assert_eq!(nonce.current(), &expected);
    }

    // Vectors below come from implementations independent of this crate:
    // OpenSSL's HKDF/AES-GCM/ChaCha20-Poly1305 and, for XChaCha20, HChaCha20
    // written out from draft-irtf-cfrg-xchacha.
    const LEGACY_VECTORS: [(AeadCipher, &str, &str, &str); 2] = [
        (
            AeadCipher::Aes192Gcm,
            "b3adc47839e047eb228870526dc8fc30b347287ffca3045d",
            "5d4ab537751e16d7258d643c6ade803a81fda83fb2962662",
            "808182838485868788898a8b8c8d8e8f9091929394959697a1c6a5ab405f14dc6ec40e4ac364b887cb\
             116a8aeacf08c7b1146304baca9c292e168200e9ed17a78377554adfb54d8fdf8a695d5f9a524306ce\
             206db56d2990fadc5836e241e9cd34eb1a54fc44c4493cde4cb9260dc5bf7f746c20f059d5bf2a3eb6\
             f7f5b2a950d0497658124294185d827301192bc35b510c",
        ),
        (
            AeadCipher::XChaCha20Poly1305,
            "b3adc47839e047eb228870526dc8fc30b347287ffca3045dcea06b3fdf090acb",
            "71a584b0a1af55a7fc631fc356a47c81ce195fdda55891868f463baa2ce68d13",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9ffecd4b72f18bf564bf\
             f2a071fb253aecadc736e98e08c989dcb6c3d61ff6a2b6754cf5fe35c1f33ae568b637b0322c10edb4\
             451ec8f588dcda0b637ad96abe612e1bc79d1c8f4920b3062bab7390ab25290b0cb508f167e873d23b\
             ee057e2ff4cca3720bce36775d523a545c3dc157aa5b46b9156bc253903f6d27005f94bed4236999a8\
             975e",
        ),
    ];

    const LEGACY_METHODS: [(AeadCipher, &str); 5] = [
        (AeadCipher::Aes128Gcm, "aes-128-gcm"),
        (AeadCipher::Aes192Gcm, "aes-192-gcm"),
        (AeadCipher::Aes256Gcm, "aes-256-gcm"),
        (AeadCipher::ChaCha20Poly1305, "chacha20-ietf-poly1305"),
        (AeadCipher::XChaCha20Poly1305, "xchacha20-ietf-poly1305"),
    ];

    const SS2022_METHODS: [(AeadCipher, &str); 3] = [
        (AeadCipher::Blake3Aes128Gcm, "2022-blake3-aes-128-gcm"),
        (AeadCipher::Blake3Aes256Gcm, "2022-blake3-aes-256-gcm"),
        (
            AeadCipher::Blake3ChaCha20Poly1305,
            "2022-blake3-chacha20-poly1305",
        ),
    ];

    fn target() -> Vec<u8> {
        encode_address(&Address::Domain("example.com".to_string(), 443))
    }

    fn unix_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// What the client has put on the wire and the server has not read yet.
    async fn sent(server: &mut DuplexStream) -> Vec<u8> {
        let mut wire = vec![0u8; 1 << 17];
        let n = server.read(&mut wire).await.unwrap();
        wire.truncate(n);
        wire
    }

    #[test]
    fn legacy_key_and_subkey_known_answers() {
        for (cipher, key, subkey, stream) in LEGACY_VECTORS {
            let derived = evp_bytes_to_key(b"barfoo!", cipher.key_len());
            assert_eq!(hex::encode(&derived), key);
            // The stream vector starts with the salt it was sealed under.
            let salt = &hex::decode(stream).unwrap()[..cipher.salt_len()];
            assert_eq!(hex::encode(cipher.derive_subkey(&derived, salt)), subkey);
        }
    }

    /// A server stream sealed by an independent implementation: a chunk, an
    /// empty chunk, another chunk.
    #[tokio::test]
    async fn legacy_server_stream_known_answer() {
        for (cipher, key, _, stream) in LEGACY_VECTORS {
            let (client_io, mut server) = tokio::io::duplex(1 << 16);
            let mut client =
                SsStream::new(client_io, cipher, hex::decode(key).unwrap(), target(), &[]);
            server
                .write_all(&hex::decode(stream).unwrap())
                .await
                .unwrap();
            drop(server);

            let mut plain = String::new();
            client.read_to_string(&mut plain).await.unwrap();
            let name = if cipher == AeadCipher::Aes192Gcm {
                "aes-192-gcm"
            } else {
                "xchacha20-ietf-poly1305"
            };
            assert_eq!(plain, format!("hello {name}bye"));
        }
    }

    /// mihomo's tunnel sends the request header at dial with an empty write
    /// (`crate::proxy::Handshake::AtDial`): it must put exactly the request
    /// on the wire, and no later empty write may add to it.
    #[tokio::test]
    async fn legacy_empty_first_write_sends_exactly_the_request() {
        for (cipher, method) in LEGACY_METHODS {
            let key = evp_bytes_to_key(b"password", cipher.key_len());
            let (client_io, mut server) = tokio::io::duplex(1 << 16);
            let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);

            assert_eq!(client.write(&[]).await.unwrap(), 0, "{method}");
            client.flush().await.unwrap();
            let wire = sent(&mut server).await;
            let (salt, chunks) = wire.split_at(cipher.salt_len());
            let mut server_key = StreamKey::new(method, &legacy_subkey(&key, salt));
            // One chunk, holding the address: salt, length and payload.
            assert_eq!(
                chunks.len(),
                2 + TAG_LEN + target().len() + TAG_LEN,
                "{method}"
            );
            assert_eq!(server_key.open_chunks(chunks), target(), "{method}");

            // The request is out: an empty write is now nothing at all.
            assert_eq!(client.write(&[]).await.unwrap(), 0);
            client.write_all(b"payload").await.unwrap();
            client.flush().await.unwrap();
            let wire = sent(&mut server).await;
            assert_eq!(wire.len(), 2 + TAG_LEN + 7 + TAG_LEN, "{method}");
            assert_eq!(server_key.open_chunks(&wire), b"payload", "{method}");
        }
    }

    #[tokio::test]
    async fn ss2022_empty_first_write_sends_exactly_the_request() {
        for (cipher, method) in SS2022_METHODS {
            let key = vec![0x42u8; cipher.key_len()];
            let (client_io, mut server) = tokio::io::duplex(1 << 16);
            let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);

            assert_eq!(client.write(&[]).await.unwrap(), 0, "{method}");
            client.flush().await.unwrap();
            let wire = sent(&mut server).await;
            let mut request = read_request_2022(method, &[&key], &wire);
            assert_eq!(request.target, target(), "{method}");
            assert!(request.timestamp.abs_diff(unix_seconds()) < 5, "{method}");
            // mihomo compat: writeRequest pads a request without payload by
            // `rand.Intn(MaxPaddingLength) + 1` bytes.
            assert!((1..=900).contains(&request.padding_len), "{method}");
            assert!(request.rest.is_empty(), "{method}");

            // The request is out: an empty write is now nothing at all.
            assert_eq!(client.write(&[]).await.unwrap(), 0);
            client.write_all(b"payload").await.unwrap();
            client.flush().await.unwrap();
            let wire = sent(&mut server).await;
            assert_eq!(wire.len(), 2 + TAG_LEN + 7 + TAG_LEN, "{method}");
            assert_eq!(request.key.open_chunks(&wire), b"payload", "{method}");
        }
    }

    /// A server that speaks first (SMTP, FTP, ...) is reached and heard
    /// before the client has sent any payload.
    #[tokio::test]
    async fn server_speaks_first_after_the_empty_write() {
        for (cipher, method) in LEGACY_METHODS {
            let key = evp_bytes_to_key(b"password", cipher.key_len());
            let (client_io, mut server) = tokio::io::duplex(1 << 16);
            let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);
            assert_eq!(client.write(&[]).await.unwrap(), 0);
            client.flush().await.unwrap();
            assert!(!sent(&mut server).await.is_empty(), "{method}");

            let salt = vec![0x99u8; cipher.salt_len()];
            let mut server_key = StreamKey::new(method, &legacy_subkey(&key, &salt));
            server.write_all(&salt).await.unwrap();
            let banner = server_key.seal_chunk(b"220 ready\r\n");
            server.write_all(&banner).await.unwrap();

            let mut banner = [0u8; 11];
            client.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"220 ready\r\n", "{method}");
        }

        for (cipher, method) in SS2022_METHODS {
            let key = vec![0x42u8; cipher.key_len()];
            let (client_io, mut server) = tokio::io::duplex(1 << 16);
            let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);
            assert_eq!(client.write(&[]).await.unwrap(), 0);
            client.flush().await.unwrap();
            let request = read_request_2022(method, &[&key], &sent(&mut server).await);

            let salt = vec![0x99u8; cipher.salt_len()];
            let (response, _) = response_2022(
                method,
                &key,
                &salt,
                &request.salt,
                unix_seconds(),
                b"220 ready\r\n",
            );
            server.write_all(&response).await.unwrap();

            let mut banner = [0u8; 11];
            client.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"220 ready\r\n", "{method}");
        }
    }

    /// mihomo compat: `internal/shadowio/reader.go` readBuffer takes whatever
    /// length the 16-bit field holds; only writers are held to 0x3FFF
    /// (legacy) and 0x7FDE (SS2022).
    #[tokio::test]
    async fn reads_a_chunk_of_any_16_bit_length() {
        let payload: Vec<u8> = (0..0xFFFFu32).map(|i| (i % 251) as u8).collect();

        let cipher = AeadCipher::Blake3Aes128Gcm;
        let key = vec![0x42u8; 16];
        let (client_io, mut server) = tokio::io::duplex(1 << 20);
        let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        client.flush().await.unwrap();
        let request =
            read_request_2022("2022-blake3-aes-128-gcm", &[&key], &sent(&mut server).await);
        let (response, mut server_key) = response_2022(
            "2022-blake3-aes-128-gcm",
            &key,
            &[0x99u8; 16],
            &request.salt,
            unix_seconds(),
            b"first",
        );
        server.write_all(&response).await.unwrap();
        server
            .write_all(&server_key.seal_chunk(&payload))
            .await
            .unwrap();
        let mut received = vec![0u8; 5 + payload.len()];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received[..5], b"first");
        assert!(received[5..] == payload[..]);

        let cipher = AeadCipher::Aes256Gcm;
        let key = evp_bytes_to_key(b"password", 32);
        let (client_io, mut server) = tokio::io::duplex(1 << 20);
        let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);
        let salt = [0x99u8; 32];
        let mut server_key = StreamKey::new("aes-256-gcm", &legacy_subkey(&key, &salt));
        server.write_all(&salt).await.unwrap();
        server
            .write_all(&server_key.seal_chunk(&payload))
            .await
            .unwrap();
        let mut received = vec![0u8; payload.len()];
        client.read_exact(&mut received).await.unwrap();
        assert!(received == payload);
    }

    /// mihomo compat: readResponse reads the first payload chunk whatever
    /// its length — an empty one is still a 16-byte tag under nonce 1, and
    /// the length-prefixed chunks start at nonce 2.
    #[tokio::test]
    async fn ss2022_response_with_an_empty_first_chunk() {
        let cipher = AeadCipher::Blake3Aes128Gcm;
        let key = vec![0x42u8; 16];
        let (client_io, mut server) = tokio::io::duplex(1 << 16);
        let mut client = SsStream::new(client_io, cipher, key.clone(), target(), &[]);
        assert_eq!(client.write(&[]).await.unwrap(), 0);
        client.flush().await.unwrap();
        let request =
            read_request_2022("2022-blake3-aes-128-gcm", &[&key], &sent(&mut server).await);
        let (response, mut server_key) = response_2022(
            "2022-blake3-aes-128-gcm",
            &key,
            &[0x99u8; 16],
            &request.salt,
            unix_seconds(),
            b"",
        );
        server.write_all(&response).await.unwrap();
        server
            .write_all(&server_key.seal_chunk(b"later"))
            .await
            .unwrap();

        let mut received = [0u8; 5];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"later");
    }

    /// How TCP requests of a mihomo client (Meta alpha-gbeb1f27) started, for
    /// several PSK lists (PSK `n` is the bytes n, n+1, ...): the salt, the
    /// identity headers and the fixed header chunk.
    #[test]
    fn ss2022_request_start_matches_mihomo() {
        let captures: [(AeadCipher, &[u8], &str); 5] = [
            (
                AeadCipher::Blake3Aes128Gcm,
                &[0],
                "31fa4203a0e0225e5a8c0f281be6c0f7d444009ffa5cef5bd1ef5408c15eec9eadaa614c9eab51461a\
                 3a0d",
            ),
            (
                AeadCipher::Blake3Aes128Gcm,
                &[0, 16],
                "3527578ad74a9eb13eadfc1b250bed4ece0236516b01a349e567f2f2363f543fade607d513965b9efc\
                 782adeb11de9c969862d4e0e7c60d3c12708",
            ),
            (
                AeadCipher::Blake3Aes128Gcm,
                &[0, 16, 32],
                "eb4f7ac00f96c824a1d4798d984c9d96b9d43324288b39803f4e7626a4189f46470a2fc7385c244797\
                 308598069cc06a786468842e50767196c8054cb07e816dd07dd8e7f3386bbac97310",
            ),
            (
                AeadCipher::Blake3Aes256Gcm,
                &[0],
                "c5966f2b2cf7254ae57b8f99c7a524d7f37188264154a02931073723acf8aa6553953e67b63680ac70\
                 985ec41531bbb82ecd06d9e6f9c188fc0bcd",
            ),
            (
                AeadCipher::Blake3Aes256Gcm,
                &[0, 100],
                "f4372403b6e5cd600bc27f18dd946e313ae164ce68112259fbf8c7f62427b1aaba9d985e5a34920a0e\
                 a2e392686ab95bbc73d64c2d1fec7c17372369bb0908b4e0ba1dd0af1b09b0870f4d",
            ),
        ];
        for (cipher, first_bytes, request) in captures {
            let psks: Vec<Vec<u8>> = first_bytes
                .iter()
                .map(|&first| (first..first + cipher.key_len() as u8).collect())
                .collect();
            let (psk, identity_psks) = psks.split_last().unwrap();
            let request = hex::decode(request).unwrap();
            let (salt, rest) = request.split_at(cipher.salt_len());
            let (identity_headers, fixed) = rest.split_at(16 * identity_psks.len());

            assert_eq!(
                hex::encode(build_identity_headers(identity_psks, psk, salt)),
                hex::encode(identity_headers),
                "{cipher:?} with {} PSKs",
                psks.len()
            );

            // The chunk after them opens under the last PSK's session key: a
            // client header announcing the address, the padding length and
            // 1 to 900 bytes of padding.
            let mut fixed = fixed.to_vec();
            CipherCore::new(cipher, cipher.derive_subkey(psk, salt))
                .decrypt_in_place(&[0u8; NONCE_LEN], &mut fixed)
                .unwrap();
            assert_eq!(fixed.len(), 11);
            assert_eq!(fixed[0], 0x00);
            let length = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
            assert!((7 + 2 + 1..=7 + 2 + 900).contains(&length));
        }
    }

    /// mihomo compat: writeExtendedIdentityHeaders — with N PSKs the request
    /// carries N-1 identity headers, each naming the next PSK under a subkey
    /// of the one before, and the session runs under the last.
    #[tokio::test]
    async fn ss2022_request_chains_identity_headers_over_every_psk() {
        for (cipher, method) in &SS2022_METHODS[..2] {
            for psk_count in [2usize, 3, 4] {
                let psks: Vec<Vec<u8>> = (0..psk_count)
                    .map(|i| vec![0x10 + i as u8; cipher.key_len()])
                    .collect();
                let (psk, identity_psks) = psks.split_last().unwrap();
                let (client_io, mut server) = tokio::io::duplex(1 << 16);
                let mut client =
                    SsStream::new(client_io, *cipher, psk.clone(), target(), identity_psks);
                assert_eq!(client.write(&[]).await.unwrap(), 0);
                client.flush().await.unwrap();

                let chain: Vec<&[u8]> = psks.iter().map(Vec::as_slice).collect();
                let request = read_request_2022(method, &chain, &sent(&mut server).await);
                assert_eq!(request.target, target(), "{method} with {psk_count} PSKs");

                // The response comes back under the last PSK alone.
                let (response, _) = response_2022(
                    method,
                    psk,
                    &vec![0x99u8; cipher.salt_len()],
                    &request.salt,
                    unix_seconds(),
                    b"ok",
                );
                server.write_all(&response).await.unwrap();
                let mut received = [0u8; 2];
                client.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"ok", "{method} with {psk_count} PSKs");
            }
        }
    }
}
