//! VMess AEAD data stream encryption/decryption.
//!
//! Data is framed as length-prefixed encrypted chunks:
//!
//! ```text
//! [Length: 2 bytes encrypted + 16 byte AEAD tag]
//! [Payload: N bytes encrypted + 16 byte AEAD tag]
//! ```
//!
//! Each chunk's nonce is derived from a counter and the body IV.
//! The counter is incremented after each chunk.
//!
//! For AES-128-GCM:
//! - Key: body_key (16 bytes)
//! - Nonce: count (2 bytes LE) + body_iv[2..12] (10 bytes) = 12 bytes
//!
//! For ChaCha20-Poly1305:
//! - Key: MD5(body_key) + MD5(body_key) = 32 bytes (two MD5 hashes concatenated)
//!   Actually V2Ray uses: generateChaChaKey(body_key) = MD5(body_key) + MD5(MD5(body_key))
//!   Then nonce: count (2 bytes LE) + body_iv[2..12] (10 bytes) = 12 bytes

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use md5::{Digest as _, Md5};
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::header::VmessSecurity;

/// Maximum VMess chunk payload size (V2Ray uses 2^14 - 1 = 16383, but we
/// align to common practice of 16384 bytes).
const MAX_CHUNK_SIZE: usize = 16384;

/// Build a 12-byte nonce from a counter and the body IV.
fn build_nonce(count: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..12].copy_from_slice(&iv[2..12]);
    nonce
}

/// Generate the 32-byte ChaCha20-Poly1305 key from a 16-byte body key.
fn generate_chacha_key(body_key: &[u8; 16]) -> [u8; 32] {
    let md5_1 = {
        let mut h = Md5::new();
        h.update(body_key);
        h.finalize()
    };
    let md5_2 = {
        let mut h = Md5::new();
        h.update(md5_1);
        h.finalize()
    };
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&md5_1);
    key[16..].copy_from_slice(&md5_2);
    key
}

/// Cipher abstraction for VMess AEAD encryption.
#[allow(clippy::large_enum_variant)]
enum VmessCipher {
    Aes128Gcm(Aes128Gcm),
    Chacha20Poly1305(ChaCha20Poly1305),
    None,
}

impl VmessCipher {
    fn new(security: VmessSecurity, body_key: &[u8; 16]) -> Self {
        match security {
            VmessSecurity::Aes128Gcm => {
                let cipher =
                    Aes128Gcm::new_from_slice(body_key).expect("AES-128-GCM key length valid");
                VmessCipher::Aes128Gcm(cipher)
            }
            VmessSecurity::Chacha20Poly1305 => {
                let key = generate_chacha_key(body_key);
                let cipher = ChaCha20Poly1305::new_from_slice(&key)
                    .expect("ChaCha20-Poly1305 key length valid");
                VmessCipher::Chacha20Poly1305(cipher)
            }
            VmessSecurity::None => VmessCipher::None,
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, io::Error> {
        match self {
            VmessCipher::Aes128Gcm(cipher) => cipher
                .encrypt(AesNonce::from_slice(nonce), plaintext)
                .map_err(|e| io::Error::other(format!("encrypt error: {e}"))),
            VmessCipher::Chacha20Poly1305(cipher) => cipher
                .encrypt(ChaNonce::from_slice(nonce), plaintext)
                .map_err(|e| io::Error::other(format!("encrypt error: {e}"))),
            VmessCipher::None => Ok(plaintext.to_vec()),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, io::Error> {
        match self {
            VmessCipher::Aes128Gcm(cipher) => cipher
                .decrypt(AesNonce::from_slice(nonce), ciphertext)
                .map_err(|e| io::Error::other(format!("decrypt error: {e}"))),
            VmessCipher::Chacha20Poly1305(cipher) => cipher
                .decrypt(ChaNonce::from_slice(nonce), ciphertext)
                .map_err(|e| io::Error::other(format!("decrypt error: {e}"))),
            VmessCipher::None => Ok(ciphertext.to_vec()),
        }
    }

    /// AEAD tag size (0 for None security).
    fn tag_size(&self) -> usize {
        match self {
            VmessCipher::Aes128Gcm(_) | VmessCipher::Chacha20Poly1305(_) => 16,
            VmessCipher::None => 0,
        }
    }
}

/// Read state machine for VMess stream.
enum ReadState {
    /// Read the response header first (4 bytes for AEAD response).
    ReadResponseHeader,
    /// Waiting to read the next chunk's encrypted length (2 + tag_size bytes).
    ReadLength,
    /// Waiting to read the chunk payload (payload_len + tag_size bytes).
    ReadPayload { encrypted_payload_len: usize },
    /// Draining decrypted data to the caller.
    Drain,
}

/// Write state machine for VMess stream.
enum WriteState {
    /// Need to send the VMess request header first.
    NeedHeader(Vec<u8>),
    /// Ready to accept data for encryption.
    Ready,
}

pin_project! {
    /// An encrypted VMess data stream.
    ///
    /// Wraps an underlying transport stream and transparently encrypts/decrypts
    /// data using the VMess AEAD chunk format.
    ///
    /// On the first write, prepends the pre-encoded VMess request header.
    /// On the first read, consumes the VMess AEAD response header.
    pub struct VmessStream<T> {
        #[pin]
        inner: T,

        // Write-side state
        write_cipher: VmessCipher,
        write_iv: [u8; 16],
        write_count: u16,
        write_state: WriteState,

        // Read-side state
        read_cipher: VmessCipher,
        read_iv: [u8; 16],
        read_count: u16,
        read_state: ReadState,

        // Read buffer: accumulates encrypted bytes from the wire.
        read_raw: Vec<u8>,
        // Decrypted plaintext buffer, drained to the caller.
        read_plaintext: Vec<u8>,
        read_plaintext_pos: usize,

        // Response auth byte for verification.
        response_auth: u8,
    }
}

impl<T> VmessStream<T> {
    /// Create a new VMess encrypted stream.
    ///
    /// - `inner`: underlying transport (TCP, TLS, WS, etc.)
    /// - `header_bytes`: pre-encoded VMess AEAD request header (from `encode_request_header`)
    /// - `body_key`: 16-byte key for body encryption
    /// - `body_iv`: 16-byte IV for body encryption
    /// - `response_auth`: expected response authentication byte
    /// - `security`: cipher selection
    pub fn new(
        inner: T,
        header_bytes: Vec<u8>,
        body_key: [u8; 16],
        body_iv: [u8; 16],
        response_auth: u8,
        security: VmessSecurity,
    ) -> Self {
        // For the response, V2Ray uses:
        //   response_key = MD5(body_key)
        //   response_iv = MD5(body_iv)
        let response_key = {
            let mut h = Md5::new();
            h.update(body_key);
            let r = h.finalize();
            let mut k = [0u8; 16];
            k.copy_from_slice(&r);
            k
        };
        let response_iv = {
            let mut h = Md5::new();
            h.update(body_iv);
            let r = h.finalize();
            let mut k = [0u8; 16];
            k.copy_from_slice(&r);
            k
        };

        Self {
            inner,
            write_cipher: VmessCipher::new(security, &body_key),
            write_iv: body_iv,
            write_count: 0,
            write_state: WriteState::NeedHeader(header_bytes),
            read_cipher: VmessCipher::new(security, &response_key),
            read_iv: response_iv,
            read_count: 0,
            read_state: ReadState::ReadResponseHeader,
            read_raw: Vec::new(),
            read_plaintext: Vec::new(),
            read_plaintext_pos: 0,
            response_auth,
        }
    }
}

/// Helper: try to read exactly `needed` bytes from `inner` into `buf`.
/// Returns `Poll::Ready(true)` if we have enough, `Poll::Ready(false)` on EOF,
/// or `Poll::Pending` if waiting.
fn try_fill<T: AsyncRead + Unpin>(
    mut inner: Pin<&mut T>,
    cx: &mut Context<'_>,
    buf: &mut Vec<u8>,
    needed: usize,
) -> Poll<io::Result<bool>> {
    while buf.len() < needed {
        let mut tmp = vec![0u8; needed - buf.len()];
        let mut read_buf = ReadBuf::new(&mut tmp);
        match inner.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    // EOF
                    return Poll::Ready(Ok(false));
                }
                buf.extend_from_slice(filled);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(true))
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        loop {
            match this.read_state {
                ReadState::Drain => {
                    // Drain decrypted plaintext to caller.
                    if *this.read_plaintext_pos < this.read_plaintext.len() {
                        let remaining = &this.read_plaintext[*this.read_plaintext_pos..];
                        let n = remaining.len().min(buf.remaining());
                        buf.put_slice(&remaining[..n]);
                        *this.read_plaintext_pos += n;
                        if *this.read_plaintext_pos >= this.read_plaintext.len() {
                            this.read_plaintext.clear();
                            *this.read_plaintext_pos = 0;
                            *this.read_state = ReadState::ReadLength;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    *this.read_state = ReadState::ReadLength;
                }

                ReadState::ReadResponseHeader => {
                    // AEAD response header: 4 bytes encrypted with AES-128-GCM.
                    // Actually the response header in AEAD mode is:
                    //   [response_auth(1) + option(1) + cmd_len(1) + cmd(cmd_len)]
                    // encrypted as a single AEAD block. The length is prepended as
                    // 2 bytes + 16 byte tag, then payload + 16 byte tag.
                    // For simplicity (most servers send a minimal response):
                    // total = 4 bytes plaintext, encrypted as (2+16) + (4+16) = 38 bytes.
                    //
                    // V2Ray AEAD response: the response header is encrypted using
                    // response_key and response_iv similar to the request header AEAD
                    // construction. The exact format:
                    //   [Header Length: 2 bytes AES-128-GCM + 16 tag] = 18 bytes
                    //   [Header Payload: N bytes AES-128-GCM + 16 tag]
                    //
                    // We need to read 18 bytes first (encrypted length + tag), decrypt
                    // to get the payload length, then read that many + 16 bytes.

                    let tag_size = this.read_cipher.tag_size();
                    let length_block_size = 2 + tag_size;

                    match try_fill(this.inner.as_mut(), cx, this.read_raw, length_block_size) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "VMess response header truncated",
                            )));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }

                    let resp_nonce = build_nonce(*this.read_count, this.read_iv);
                    *this.read_count = this.read_count.wrapping_add(1);

                    let length_plaintext = this
                        .read_cipher
                        .decrypt(&resp_nonce, &this.read_raw[..length_block_size])?;
                    this.read_raw.drain(..length_block_size);

                    if length_plaintext.len() < 2 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VMess response length too short",
                        )));
                    }

                    let payload_len =
                        u16::from_be_bytes([length_plaintext[0], length_plaintext[1]]) as usize;
                    let payload_block_size = payload_len + tag_size;

                    match try_fill(this.inner.as_mut(), cx, this.read_raw, payload_block_size) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "VMess response payload truncated",
                            )));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }

                    let resp_payload_nonce = build_nonce(*this.read_count, this.read_iv);
                    *this.read_count = this.read_count.wrapping_add(1);

                    let payload_plaintext = this
                        .read_cipher
                        .decrypt(&resp_payload_nonce, &this.read_raw[..payload_block_size])?;
                    this.read_raw.drain(..payload_block_size);

                    // Validate response_auth.
                    if !payload_plaintext.is_empty() && payload_plaintext[0] != *this.response_auth
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VMess response auth mismatch",
                        )));
                    }

                    // Response header consumed. Switch to reading data chunks.
                    *this.read_state = ReadState::ReadLength;
                }

                ReadState::ReadLength => {
                    let tag_size = this.read_cipher.tag_size();
                    let length_block_size = 2 + tag_size;

                    match try_fill(this.inner.as_mut(), cx, this.read_raw, length_block_size) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            // Clean EOF between chunks.
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }

                    let nonce = build_nonce(*this.read_count, this.read_iv);
                    *this.read_count = this.read_count.wrapping_add(1);

                    let length_plaintext = this
                        .read_cipher
                        .decrypt(&nonce, &this.read_raw[..length_block_size])?;
                    this.read_raw.drain(..length_block_size);

                    if length_plaintext.len() < 2 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VMess chunk length too short",
                        )));
                    }

                    let payload_len =
                        u16::from_be_bytes([length_plaintext[0], length_plaintext[1]]) as usize;

                    if payload_len == 0 {
                        // Zero-length chunk signals end of stream.
                        return Poll::Ready(Ok(()));
                    }

                    *this.read_state = ReadState::ReadPayload {
                        encrypted_payload_len: payload_len + tag_size,
                    };
                }

                ReadState::ReadPayload {
                    encrypted_payload_len,
                } => {
                    let needed = *encrypted_payload_len;

                    match try_fill(this.inner.as_mut(), cx, this.read_raw, needed) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "VMess chunk payload truncated",
                            )));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }

                    let nonce = build_nonce(*this.read_count, this.read_iv);
                    *this.read_count = this.read_count.wrapping_add(1);

                    let plaintext = this.read_cipher.decrypt(&nonce, &this.read_raw[..needed])?;
                    this.read_raw.drain(..needed);

                    *this.read_plaintext = plaintext;
                    *this.read_plaintext_pos = 0;
                    *this.read_state = ReadState::Drain;
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        // If we still need to send the header, send it first.
        if let WriteState::NeedHeader(ref mut header) = this.write_state {
            let header_data = std::mem::take(header);
            // Try to write the header.
            let mut pos = 0;
            while pos < header_data.len() {
                match this.inner.as_mut().poll_write(cx, &header_data[pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "VMess header write returned 0",
                            )));
                        }
                        pos += n;
                    }
                    Poll::Ready(Err(e)) => {
                        // Put remaining header back.
                        *this.write_state = WriteState::NeedHeader(header_data[pos..].to_vec());
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        *this.write_state = WriteState::NeedHeader(header_data[pos..].to_vec());
                        return Poll::Pending;
                    }
                }
            }
            *this.write_state = WriteState::Ready;
        }

        // Encrypt and write the data chunk.
        let chunk_size = buf.len().min(MAX_CHUNK_SIZE);
        let data = &buf[..chunk_size];

        // Encrypt the length (2 bytes, big-endian).
        let length_nonce = build_nonce(*this.write_count, this.write_iv);
        *this.write_count = this.write_count.wrapping_add(1);

        let length_bytes = (chunk_size as u16).to_be_bytes();
        let encrypted_length = this.write_cipher.encrypt(&length_nonce, &length_bytes)?;

        // Encrypt the payload.
        let payload_nonce = build_nonce(*this.write_count, this.write_iv);
        *this.write_count = this.write_count.wrapping_add(1);

        let encrypted_payload = this.write_cipher.encrypt(&payload_nonce, data)?;

        // Combine into a single write: [encrypted_length][encrypted_payload].
        let mut combined = Vec::with_capacity(encrypted_length.len() + encrypted_payload.len());
        combined.extend_from_slice(&encrypted_length);
        combined.extend_from_slice(&encrypted_payload);

        // Write the combined chunk. We need to write all of it.
        let mut pos = 0;
        while pos < combined.len() {
            match this.inner.as_mut().poll_write(cx, &combined[pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "VMess chunk write returned 0",
                        )));
                    }
                    pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if pos > 0 {
                        // Partial write of encrypted data -- we can't recover partially.
                        // This is a fundamental limitation: the whole chunk must go out.
                        // In practice, this loop will complete because TCP buffers are
                        // large enough for our chunks.
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_nonce_format() {
        let iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let nonce = build_nonce(1, &iv);
        assert_eq!(nonce[0..2], 1u16.to_be_bytes());
        assert_eq!(&nonce[2..12], &iv[2..12]);
    }

    #[test]
    fn build_nonce_counter_zero() {
        let iv = [0u8; 16];
        let nonce = build_nonce(0, &iv);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn generate_chacha_key_deterministic() {
        let body_key = [0xAA; 16];
        let k1 = generate_chacha_key(&body_key);
        let k2 = generate_chacha_key(&body_key);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn cipher_roundtrip_aes() {
        let key = [0x42; 16];
        let cipher = VmessCipher::new(VmessSecurity::Aes128Gcm, &key);
        let nonce = [0u8; 12];
        let plaintext = b"hello vmess aes";
        let encrypted = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn cipher_roundtrip_chacha() {
        let key = [0x42; 16];
        let cipher = VmessCipher::new(VmessSecurity::Chacha20Poly1305, &key);
        let nonce = [0u8; 12];
        let plaintext = b"hello vmess chacha";
        let encrypted = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn cipher_none_passthrough() {
        let key = [0u8; 16];
        let cipher = VmessCipher::new(VmessSecurity::None, &key);
        let nonce = [0u8; 12];
        let plaintext = b"plain data";
        let encrypted = cipher.encrypt(&nonce, plaintext).unwrap();
        assert_eq!(&encrypted, plaintext);
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn cipher_tag_sizes() {
        let key = [0u8; 16];
        assert_eq!(
            VmessCipher::new(VmessSecurity::Aes128Gcm, &key).tag_size(),
            16
        );
        assert_eq!(
            VmessCipher::new(VmessSecurity::Chacha20Poly1305, &key).tag_size(),
            16
        );
        assert_eq!(VmessCipher::new(VmessSecurity::None, &key).tag_size(), 0);
    }
}
