use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::addr::Address;

/// Maximum payload size per chunk.
/// Legacy AEAD: 0x3FFF (16383 bytes)
/// SS2022: 0xFFFF (65535 bytes)
const MAX_PAYLOAD_SIZE: usize = 0x3FFF;
const MAX_PAYLOAD_SIZE_2022: usize = 0x7FDE; // buf.BufferSize - 2 - 32 = 32734 (mihomo compat)

/// AEAD tag size for all supported ciphers (16 bytes).
const TAG_LEN: usize = 16;

/// Nonce size for all supported AEAD ciphers (12 bytes).
const NONCE_LEN: usize = 12;

/// Supported AEAD cipher types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
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
            "aes-256-gcm" => Some(AeadCipher::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(AeadCipher::ChaCha20Poly1305),
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
            AeadCipher::Aes256Gcm
            | AeadCipher::ChaCha20Poly1305
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
            let mut context_material = Vec::with_capacity(key.len() + salt.len());
            context_material.extend_from_slice(key);
            context_material.extend_from_slice(salt);
            let mut out = vec![0u8; self.key_len()];
            let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
            hasher.update(&context_material);
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

/// Encode an Address into shadowsocks address header bytes.
///
/// Format: [addr_type(1)][addr_data][port(2 big-endian)]
///   addr_type 1 = IPv4 (4 bytes)
///   addr_type 3 = domain (1 byte length + domain bytes)
///   addr_type 4 = IPv6 (16 bytes)
pub fn encode_address(addr: &Address) -> Vec<u8> {
    // Pre-allocate based on address type: IPv4=7, IPv6=19, Domain=4+len
    let cap = match addr {
        Address::Ip(sa) => match sa.ip() {
            std::net::IpAddr::V4(_) => 7,
            std::net::IpAddr::V6(_) => 19,
        },
        Address::Domain(d, _) => 4 + d.len(),
    };
    let mut buf = Vec::with_capacity(cap);
    match addr {
        Address::Ip(sockaddr) => match sockaddr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                buf.push(0x01);
                buf.extend_from_slice(&ipv4.octets());
                buf.extend_from_slice(&sockaddr.port().to_be_bytes());
            }
            std::net::IpAddr::V6(ipv6) => {
                buf.push(0x04);
                buf.extend_from_slice(&ipv6.octets());
                buf.extend_from_slice(&sockaddr.port().to_be_bytes());
            }
        },
        Address::Domain(domain, port) => {
            buf.push(0x03);
            let domain_bytes = domain.as_bytes();
            buf.push(domain_bytes.len() as u8);
            buf.extend_from_slice(domain_bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// Encrypt/decrypt dispatcher that works with any of the supported AEAD ciphers.
struct CipherCore {
    cipher: AeadCipher,
    key: Vec<u8>,
}

impl CipherCore {
    fn new(cipher: AeadCipher, key: Vec<u8>) -> Self {
        Self { cipher, key }
    }

    /// Encrypt `data` in-place using the given nonce, appending the AEAD tag.
    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        data: &mut Vec<u8>,
    ) -> Result<(), io::Error> {
        let nonce_ga = GenericArray::from_slice(nonce);
        match self.cipher {
            AeadCipher::Aes128Gcm | AeadCipher::Blake3Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key));
                cipher
                    .encrypt_in_place(nonce_ga, b"", data)
                    .map_err(|e| io::Error::other(format!("aes-128-gcm encrypt: {e}")))
            }
            AeadCipher::Aes256Gcm | AeadCipher::Blake3Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                cipher
                    .encrypt_in_place(nonce_ga, b"", data)
                    .map_err(|e| io::Error::other(format!("aes-256-gcm encrypt: {e}")))
            }
            AeadCipher::ChaCha20Poly1305 | AeadCipher::Blake3ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                cipher
                    .encrypt_in_place(nonce_ga, b"", data)
                    .map_err(|e| io::Error::other(format!("chacha20-poly1305 encrypt: {e}")))
            }
        }
    }

    /// Decrypt `data` in-place (data includes the appended AEAD tag).
    fn decrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        data: &mut Vec<u8>,
    ) -> Result<(), io::Error> {
        let nonce_ga = GenericArray::from_slice(nonce);
        match self.cipher {
            AeadCipher::Aes128Gcm | AeadCipher::Blake3Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key));
                cipher.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("aes-128-gcm decrypt: {e}"),
                    )
                })
            }
            AeadCipher::Aes256Gcm | AeadCipher::Blake3Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                cipher.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("aes-256-gcm decrypt: {e}"),
                    )
                })
            }
            AeadCipher::ChaCha20Poly1305 | AeadCipher::Blake3ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                cipher.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("chacha20-poly1305 decrypt: {e}"),
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

/// Internal states for the write (encrypt) half.
enum WriteState {
    /// Ready to accept data for encryption.
    Ready,
    /// We have encrypted data that needs to be flushed to the inner writer.
    Flushing { buf: Vec<u8>, pos: usize },
    /// SS2022: waiting for first user data to bundle with the address header.
    /// The first poll_write builds the complete initial request including user data.
    #[allow(dead_code)]
    WaitingFirstData {
        salt: Vec<u8>,
        addr_header: Vec<u8>,
        identity_server_key: Option<Vec<u8>>,
        identity_user_key: Option<Vec<u8>>,
    },
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

        // SS2022 multi-user: the key used for response decryption session derivation.
        // For single-user this is the same as master_key.
        // For multi-user this is the user_key (second part after ':').
        session_key: Vec<u8>,

        // Encrypt state (write path)
        enc_cipher: Option<CipherCore>,
        enc_nonce: NonceCounter,
        write_state: WriteState,

        // Decrypt state (read path)
        dec_cipher: Option<CipherCore>,
        dec_nonce: NonceCounter,
        read_state: ReadState,
    }
}

impl<T> SsStream<T> {
    /// Create a new SsStream wrapping the given inner stream.
    ///
    /// `master_key` is derived from the password via evp_bytes_to_key (legacy) or base64-decoded (SS2022).
    /// `cipher` specifies which AEAD cipher to use.
    /// `initial_payload` is the first data to send (typically the address header for legacy,
    /// or the SOCKS address header for SS2022).
    /// `identity_keys` is for SS2022 multi-user mode: `Some((server_key, user_key))`.
    ///   When present, the identity header is derived from server_key and the session
    ///   encryption uses user_key. When `None`, master_key is used for everything.
    pub fn new(
        inner: T,
        cipher: AeadCipher,
        master_key: Vec<u8>,
        initial_payload: Vec<u8>,
        identity_keys: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        let is_ss2022 = cipher.is_ss2022();

        // Generate random salt for the encryption direction
        let salt = generate_salt(cipher.salt_len());

        // For SS2022 multi-user, the session key is derived from the USER key,
        // and the identity header uses the SERVER key.
        // For single-user or legacy, session key = master_key.
        let (session_key, identity) = if let Some((ref server_key, ref user_key)) = identity_keys {
            (user_key.clone(), Some(server_key.clone()))
        } else {
            (master_key.clone(), None)
        };

        // Derive the encryption subkey from session key + salt
        let enc_subkey = cipher.derive_subkey(&session_key, &salt);
        let enc_cipher = CipherCore::new(cipher, enc_subkey);

        // Keep a copy of the salt for SS2022 response header verification
        let request_salt = if is_ss2022 { salt.clone() } else { Vec::new() };

        // For SS2022: send the initial request immediately (non-early mode),
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
                cipher,
                identity.as_deref(),
                identity_keys.as_ref().map(|(_, uk)| uk.as_slice()),
                &[], // No early payload — send addr+padding only (like mihomo DialConn)
            );
            (WriteState::Flushing { buf, pos: 0 }, nonce)
        } else {
            let mut nonce = NonceCounter::new();
            let buf = build_initial_buffer(&salt, &enc_cipher, &mut nonce, &initial_payload);
            (WriteState::Flushing { buf, pos: 0 }, nonce)
        };

        Self {
            inner,
            cipher_type: cipher,
            is_ss2022,
            request_salt,
            session_key,
            enc_cipher: Some(enc_cipher),
            enc_nonce,
            write_state,
            dec_cipher: None,
            dec_nonce: NonceCounter::new(),
            read_state: ReadState::WaitingSalt { buf: Vec::new() },
        }
    }

    /// Flush the initial handshake buffer to the wire immediately.
    ///
    /// mihomo compat: mihomo's DialConn writes the SS2022 request to the TCP
    /// connection before returning. We must do the same so the server starts
    /// processing before the relay begins. Without this, tokio::io::split's
    /// BiLock can cause a deadlock where the read side blocks waiting for the
    /// server response while the write side hasn't sent the handshake yet.
    pub async fn flush_handshake(&mut self) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        if let WriteState::Flushing { ref buf, ref mut pos } = self.write_state {
            if *pos < buf.len() {
                let data = buf[*pos..].to_vec();
                self.inner.write_all(&data).await?;
                self.inner.flush().await?;
            }
        }
        self.write_state = WriteState::Ready;
        Ok(())
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
/// [salt][identity_header (16 bytes, if multi-user)][encrypted_request_header + tag(16)]
///
/// The request header plaintext is:
///   [0x00 (client type)][timestamp_be(8)][variable_length_be(2)][socks_addr][padding_len_be(2)][padding][initial_data]
///
/// The entire header is encrypted as ONE AEAD chunk (nonce=0).
/// After the header, subsequent data uses standard length-prefixed chunks (nonce continues).
///
/// For multi-user mode:
///   `server_key` = Some(server PSK) -- used to derive the identity subkey
///   `user_key` = Some(user PSK) -- its hash is encrypted as the identity header
///   The session cipher (passed in `cipher`) must already be derived from the user_key.
#[allow(clippy::too_many_arguments)]
fn build_ss2022_request_buffer(
    salt: &[u8],
    cipher: &CipherCore,
    nonce: &mut NonceCounter,
    addr_header: &[u8],
    cipher_type: AeadCipher,
    server_key: Option<&[u8]>,
    user_key: Option<&[u8]>,
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

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();

    // Data chunk plaintext: [socks_addr][padding_len(2)][padding][first_user_data]
    // When first_data is non-empty, padding=0. When empty, random 0-900 padding.
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
        server_key.is_some(),
    );

    let mut buf = Vec::with_capacity(
        salt.len() + 16 + (header.len() + TAG_LEN) + (data_payload.len() + TAG_LEN),
    );

    // [1] Salt (plaintext)
    buf.extend_from_slice(salt);

    // [2] EIH (identity header, AES-ECB encrypted, multi-user only)
    if let (Some(server_key), Some(user_key)) = (server_key, user_key) {
        let identity_header =
            build_identity_header(server_key, user_key, salt, cipher_type.key_len());
        buf.extend_from_slice(&identity_header);
    }

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

    tracing::info!(
        "SS2022 wire: total={} (salt={} eih={} header={} data={})",
        buf.len(),
        salt.len(),
        if server_key.is_some() { 16 } else { 0 },
        header.len(),
        data_payload.len(),
    );

    buf
}

/// Build the 16-byte identity header for SS2022 multi-user mode.
///
/// 1. Derive identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", server_psk || salt)
/// 2. Compute psk_hash = blake3::hash(user_psk)[0..16]
/// 3. AES-ECB encrypt psk_hash with identity_subkey[0..16]
fn build_identity_header(
    server_key: &[u8],
    user_key: &[u8],
    salt: &[u8],
    key_len: usize,
) -> [u8; 16] {
    // Derive identity subkey
    let mut context_material = Vec::with_capacity(server_key.len() + salt.len());
    context_material.extend_from_slice(server_key);
    context_material.extend_from_slice(salt);
    let mut identity_subkey = vec![0u8; key_len];
    let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
    hasher.update(&context_material);
    hasher.finalize_xof().fill(&mut identity_subkey);

    // Compute psk_hash = blake3::hash(user_psk)[0..16]
    let user_hash = blake3::hash(user_key);
    let mut psk_hash = [0u8; 16];
    psk_hash.copy_from_slice(&user_hash.as_bytes()[..16]);

    // AES-ECB encrypt psk_hash with identity_subkey.
    // Key size matches the cipher: AES-128 for 16-byte keys, AES-256 for 32-byte keys.
    let mut block = aes::Block::from(psk_hash);
    match key_len {
        16 => {
            let aes_key = GenericArray::from_slice(&identity_subkey[..16]);
            aes::Aes128::new(aes_key).encrypt_block(&mut block);
        }
        32 => {
            use aes::cipher::KeyInit as _;
            let aes_key =
                aes::cipher::generic_array::GenericArray::from_slice(&identity_subkey[..32]);
            aes::Aes256::new(aes_key).encrypt_block(&mut block);
        }
        _ => {
            // Fallback to AES-128 with first 16 bytes
            let aes_key = GenericArray::from_slice(&identity_subkey[..16]);
            aes::Aes128::new(aes_key).encrypt_block(&mut block);
        }
    }

    block.into()
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
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let nonce_ga = GenericArray::from_slice(nonce);
    match cipher {
        AeadCipher::Aes128Gcm | AeadCipher::Blake3Aes128Gcm => {
            let c = Aes128Gcm::new(GenericArray::from_slice(key));
            c.encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| anyhow::anyhow!("aes-128-gcm encrypt: {e}"))
        }
        AeadCipher::Aes256Gcm | AeadCipher::Blake3Aes256Gcm => {
            let c = Aes256Gcm::new(GenericArray::from_slice(key));
            c.encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| anyhow::anyhow!("aes-256-gcm encrypt: {e}"))
        }
        AeadCipher::ChaCha20Poly1305 | AeadCipher::Blake3ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            c.encrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| anyhow::anyhow!("chacha20-poly1305 encrypt: {e}"))
        }
    }
}

/// Standalone AEAD decrypt for UDP packets (each packet uses a fresh key/nonce).
pub(super) fn decrypt_in_place_standalone(
    cipher: &AeadCipher,
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    data: &mut Vec<u8>,
) -> anyhow::Result<()> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let nonce_ga = GenericArray::from_slice(nonce);
    match cipher {
        AeadCipher::Aes128Gcm | AeadCipher::Blake3Aes128Gcm => {
            let c = Aes128Gcm::new(GenericArray::from_slice(key));
            c.decrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| anyhow::anyhow!("aes-128-gcm decrypt: {e}"))
        }
        AeadCipher::Aes256Gcm | AeadCipher::Blake3Aes256Gcm => {
            let c = Aes256Gcm::new(GenericArray::from_slice(key));
            c.decrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| anyhow::anyhow!("aes-256-gcm decrypt: {e}"))
        }
        AeadCipher::ChaCha20Poly1305 | AeadCipher::Blake3ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            c.decrypt_in_place(nonce_ga, b"", data)
                .map_err(|e| anyhow::anyhow!("chacha20-poly1305 decrypt: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
        assert_eq!(AeadCipher::from_name("unknown"), None);
    }

    #[test]
    fn cipher_key_lengths() {
        assert_eq!(AeadCipher::Aes128Gcm.key_len(), 16);
        assert_eq!(AeadCipher::Aes256Gcm.key_len(), 32);
        assert_eq!(AeadCipher::ChaCha20Poly1305.key_len(), 32);
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
            AeadCipher::Blake3Aes256Gcm,
            None,
            None,
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
            AeadCipher::Blake3Aes128Gcm,
            None,
            None,
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
        let mut client = SsStream::new(client_io, cipher, key.clone(), addr_header.clone(), None);

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
            let payload_len =
                u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;

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
            AeadCipher::Blake3Aes256Gcm,
            None,
            None,
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
                    let now_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("system time before epoch")
                        .as_secs();
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
                    if data_length > 0 {
                        *me.read_state = ReadState::WaitingPayload {
                            buf: Vec::new(),
                            payload_len: data_length,
                        };
                    } else {
                        // data_length == 0: no data chunk sent, standard chunks at nonce=1
                        *me.read_state = ReadState::WaitingLength { buf: Vec::new() };
                    }
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

                    // Parse the 2-byte big-endian length
                    let payload_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
                    let max_payload = if *me.is_ss2022 {
                        MAX_PAYLOAD_SIZE_2022
                    } else {
                        MAX_PAYLOAD_SIZE
                    };
                    if payload_len > max_payload {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("payload length {payload_len} exceeds maximum {max_payload}"),
                        )));
                    }

                    *me.read_state = ReadState::WaitingPayload {
                        buf: Vec::new(),
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
                        *me.read_state = ReadState::WaitingLength { buf: Vec::new() };
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

        // SS2022: if this is the first write, build the initial request
        // bundling user data with the address header.
        if let WriteState::WaitingFirstData { .. } = me.write_state {
            // Take ownership of the state data
            let (salt, addr_header, id_sk, id_uk) = if let WriteState::WaitingFirstData {
                salt,
                addr_header,
                identity_server_key,
                identity_user_key,
            } =
                std::mem::replace(me.write_state, WriteState::Ready)
            {
                (salt, addr_header, identity_server_key, identity_user_key)
            } else {
                unreachable!()
            };

            let enc = me
                .enc_cipher
                .as_ref()
                .ok_or_else(|| io::Error::other("encryption cipher not initialized"))?;

            let initial_buf = build_ss2022_request_buffer(
                &salt,
                enc,
                me.enc_nonce,
                &addr_header,
                *me.cipher_type,
                id_sk.as_deref(),
                id_uk.as_deref(),
                data, // Bundle first user data!
            );

            let consumed = data.len(); // All user data consumed into the initial buffer
            *me.write_state = WriteState::Flushing {
                buf: initial_buf,
                pos: 0,
            };

            // Fall through to the Flushing handler below, but report all
            // user data as consumed
            // First try to flush what we can
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
                        Poll::Pending => {
                            // Data is buffered, will flush later. Report user data consumed.
                            return Poll::Ready(Ok(consumed));
                        }
                    }
                }
                *me.write_state = WriteState::Ready;
            }
            return Poll::Ready(Ok(consumed));
        }

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
            *me.write_state = WriteState::Ready;
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

        let mut out = Vec::with_capacity(2 + TAG_LEN + chunk_len + TAG_LEN);

        // Encrypt length
        let mut len_buf = Vec::from([(chunk_len >> 8) as u8, (chunk_len & 0xFF) as u8]);
        enc.encrypt_in_place(me.enc_nonce.current(), &mut len_buf)?;
        me.enc_nonce.increment();
        out.extend_from_slice(&len_buf);

        // Encrypt payload
        let mut payload_buf = chunk.to_vec();
        enc.encrypt_in_place(me.enc_nonce.current(), &mut payload_buf)?;
        me.enc_nonce.increment();
        out.extend_from_slice(&payload_buf);

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
        *me.write_state = WriteState::Ready;

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
