use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::addr::Address;

/// Maximum payload size per chunk (0x3FFF = 16383 bytes).
const MAX_PAYLOAD_SIZE: usize = 0x3FFF;

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
}

impl AeadCipher {
    /// Parse cipher name from config string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "aes-128-gcm" => Some(AeadCipher::Aes128Gcm),
            "aes-256-gcm" => Some(AeadCipher::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(AeadCipher::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            AeadCipher::Aes128Gcm => 16,
            AeadCipher::Aes256Gcm => 32,
            AeadCipher::ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes (same as key length for AEAD ciphers).
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    /// Derive a subkey from the master key and salt using HKDF-SHA1.
    fn derive_subkey(&self, key: &[u8], salt: &[u8]) -> Vec<u8> {
        hkdf_sha1(key, salt, b"ss-subkey", self.key_len())
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
    let mut prev = Vec::new();

    for i in 0..count {
        let mut hasher = md5::Md5::new();
        if i > 0 {
            hasher.update(&prev);
        }
        hasher.update(password);

        prev = hasher.finalize().to_vec();
        result.extend_from_slice(&prev);
    }

    result.truncate(key_len);
    result
}

/// HKDF-SHA1 key derivation (used to derive per-session subkeys).
fn hkdf_sha1(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let s = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = ring::hmac::sign(&s, ikm);

    let mut okm = Vec::with_capacity(out_len);
    let mut t = Vec::new();
    let mut counter: u8 = 1;

    while okm.len() < out_len {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, prk.as_ref());
        let mut data = Vec::new();
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(counter);
        let tag = ring::hmac::sign(&key, &data);
        t = tag.as_ref().to_vec();
        okm.extend_from_slice(&t);
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
    let mut buf = Vec::new();
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
            AeadCipher::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key));
                cipher
                    .encrypt_in_place(nonce_ga, b"", data)
                    .map_err(|e| io::Error::other(format!("aes-128-gcm encrypt: {}", e)))
            }
            AeadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                cipher
                    .encrypt_in_place(nonce_ga, b"", data)
                    .map_err(|e| io::Error::other(format!("aes-256-gcm encrypt: {}", e)))
            }
            AeadCipher::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                cipher
                    .encrypt_in_place(nonce_ga, b"", data)
                    .map_err(|e| io::Error::other(format!("chacha20-poly1305 encrypt: {}", e)))
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
            AeadCipher::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.key));
                cipher.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("aes-128-gcm decrypt: {}", e),
                    )
                })
            }
            AeadCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                cipher.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("aes-256-gcm decrypt: {}", e),
                    )
                })
            }
            AeadCipher::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.key));
                cipher.decrypt_in_place(nonce_ga, b"", data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("chacha20-poly1305 decrypt: {}", e),
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
}

/// Internal states for the read (decrypt) half.
enum ReadState {
    /// We need to read the salt from the remote server first.
    WaitingSalt { buf: Vec<u8> },
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
    /// Wire format (client -> server):
    ///   [salt][encrypted_length(2) + tag(16)][encrypted_payload + tag(16)] ...
    ///
    /// The first payload chunk contains the target address header.
    pub struct SsStream<T> {
        #[pin]
        inner: T,
        cipher_type: AeadCipher,
        master_key: Vec<u8>,

        // Encrypt state (write path)
        enc_cipher: Option<CipherCore>,
        enc_nonce: NonceCounter,
        write_state: WriteState,
        salt_sent: bool,

        // Decrypt state (read path)
        dec_cipher: Option<CipherCore>,
        dec_nonce: NonceCounter,
        read_state: ReadState,
    }
}

impl<T> SsStream<T> {
    /// Create a new SsStream wrapping the given inner stream.
    ///
    /// `master_key` is derived from the password via evp_bytes_to_key.
    /// `cipher` specifies which AEAD cipher to use.
    /// `initial_payload` is the first data to send (typically the address header + first data).
    pub fn new(
        inner: T,
        cipher: AeadCipher,
        master_key: Vec<u8>,
        initial_payload: Vec<u8>,
    ) -> Self {
        // Generate random salt for the encryption direction
        let salt = generate_salt(cipher.salt_len());

        // Derive the encryption subkey from master key + salt
        let enc_subkey = cipher.derive_subkey(&master_key, &salt);
        let enc_cipher = CipherCore::new(cipher, enc_subkey);

        // Build the initial write buffer: salt + encrypted first chunk(s)
        let mut enc_nonce = NonceCounter::new();
        let initial_buf =
            build_initial_buffer(&salt, &enc_cipher, &mut enc_nonce, &initial_payload);

        Self {
            inner,
            cipher_type: cipher,
            master_key,
            enc_cipher: Some(enc_cipher),
            enc_nonce,
            write_state: WriteState::Flushing {
                buf: initial_buf,
                pos: 0,
            },
            salt_sent: true,
            dec_cipher: None,
            dec_nonce: NonceCounter::new(),
            read_state: ReadState::WaitingSalt { buf: Vec::new() },
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
        let mut len_buf = vec![((chunk_len >> 8) & 0xFF) as u8, (chunk_len & 0xFF) as u8];
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

/// Generate a random salt of the given length.
fn generate_salt(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
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

                    // Derive decryption subkey from master key + received salt
                    let dec_subkey = me.cipher_type.derive_subkey(me.master_key, salt_buf);
                    *me.dec_cipher = Some(CipherCore::new(*me.cipher_type, dec_subkey));

                    // Transition to reading length
                    *me.read_state = ReadState::WaitingLength { buf: Vec::new() };
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
                    if payload_len > MAX_PAYLOAD_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "payload length {} exceeds maximum {}",
                                payload_len, MAX_PAYLOAD_SIZE
                            ),
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

        // First, flush any pending data
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

        // Take at most MAX_PAYLOAD_SIZE bytes
        let chunk_len = std::cmp::min(MAX_PAYLOAD_SIZE, data.len());
        let chunk = &data[..chunk_len];

        let mut out = Vec::with_capacity(2 + TAG_LEN + chunk_len + TAG_LEN);

        // Encrypt length
        let mut len_buf = vec![((chunk_len >> 8) & 0xFF) as u8, (chunk_len & 0xFF) as u8];
        enc.encrypt_in_place(me.enc_nonce.current(), &mut len_buf)?;
        me.enc_nonce.increment();
        out.extend_from_slice(&len_buf);

        // Encrypt payload
        let mut payload_buf = chunk.to_vec();
        enc.encrypt_in_place(me.enc_nonce.current(), &mut payload_buf)?;
        me.enc_nonce.increment();
        out.extend_from_slice(&payload_buf);

        // Try to write as much as possible right now
        match me.inner.as_mut().poll_write(cx, &out) {
            Poll::Ready(Ok(n)) => {
                if n < out.len() {
                    // Partial write - buffer the rest
                    *me.write_state = WriteState::Flushing { buf: out, pos: n };
                }
                // We consumed chunk_len bytes of the caller's data
                Poll::Ready(Ok(chunk_len))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Buffer all encrypted data for later
                *me.write_state = WriteState::Flushing { buf: out, pos: 0 };
                // We consumed chunk_len of plaintext
                Poll::Ready(Ok(chunk_len))
            }
        }
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
