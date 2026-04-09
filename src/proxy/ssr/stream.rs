//! SSR stream cipher wrapper.
//!
//! ShadowsocksR uses legacy stream ciphers (not AEAD). The key derivation is
//! the same `evp_bytes_to_key` as classic Shadowsocks. The first N bytes
//! written to the stream are the randomly-generated IV (initialization vector),
//! and the first N bytes read from the stream are the server's IV.
//!
//! Supported ciphers:
//! - `aes-256-cfb` (most common)
//! - `aes-128-cfb`
//! - `chacha20-ietf`
//! - `none` (passthrough, no encryption)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::shadowsocks::aead::evp_bytes_to_key;

/// Supported SSR stream cipher types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrCipher {
    None,
    Aes128Cfb,
    Aes256Cfb,
    ChaCha20Ietf,
    Rc4Md5,
}

impl SsrCipher {
    /// Parse cipher name from config string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "none" | "plain" | "table" => Some(SsrCipher::None),
            "aes-128-cfb" | "aes-128-cfb128" => Some(SsrCipher::Aes128Cfb),
            "aes-256-cfb" | "aes-256-cfb128" => Some(SsrCipher::Aes256Cfb),
            "chacha20-ietf" => Some(SsrCipher::ChaCha20Ietf),
            "rc4-md5" => Some(SsrCipher::Rc4Md5),
            _ => None,
        }
    }

    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            SsrCipher::None => 0,
            SsrCipher::Aes128Cfb => 16,
            SsrCipher::Aes256Cfb => 32,
            SsrCipher::ChaCha20Ietf => 32,
            SsrCipher::Rc4Md5 => 16,
        }
    }

    /// IV (initialization vector) length in bytes.
    pub fn iv_len(&self) -> usize {
        match self {
            SsrCipher::None => 0,
            SsrCipher::Aes128Cfb => 16,
            SsrCipher::Aes256Cfb => 16,
            SsrCipher::ChaCha20Ietf => 12,
            SsrCipher::Rc4Md5 => 16,
        }
    }
}

/// A stream cipher instance that can encrypt or decrypt data in-place.
///
/// Uses `BufEncryptor`/`BufDecryptor` for CFB modes since they support
/// incremental `&mut self` encrypt/decrypt across multiple calls (unlike
/// the non-buffered variants which consume `self`).
enum CipherInstance {
    None,
    Aes128CfbEnc(cfb_mode::BufEncryptor<aes::Aes128>),
    Aes256CfbEnc(cfb_mode::BufEncryptor<aes::Aes256>),
    Aes128CfbDec(cfb_mode::BufDecryptor<aes::Aes128>),
    Aes256CfbDec(cfb_mode::BufDecryptor<aes::Aes256>),
    ChaCha20Ietf(chacha20::ChaCha20),
    Rc4(Rc4State),
}

impl CipherInstance {
    /// Create an encryption cipher instance from type, key, and IV.
    fn new_encrypt(cipher: SsrCipher, key: &[u8], iv: &[u8]) -> Self {
        use cipher::KeyIvInit;

        match cipher {
            SsrCipher::None => CipherInstance::None,
            SsrCipher::Aes128Cfb => {
                let enc = cfb_mode::BufEncryptor::<aes::Aes128>::new_from_slices(key, iv)
                    .expect("aes-128-cfb: invalid key/iv length");
                CipherInstance::Aes128CfbEnc(enc)
            }
            SsrCipher::Aes256Cfb => {
                let enc = cfb_mode::BufEncryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .expect("aes-256-cfb: invalid key/iv length");
                CipherInstance::Aes256CfbEnc(enc)
            }
            SsrCipher::ChaCha20Ietf => {
                let c = chacha20::ChaCha20::new_from_slices(key, iv)
                    .expect("chacha20-ietf: invalid key/iv length");
                CipherInstance::ChaCha20Ietf(c)
            }
            SsrCipher::Rc4Md5 => {
                let derived_key = rc4_md5_key(key, iv);
                CipherInstance::Rc4(Rc4State::new(&derived_key))
            }
        }
    }

    /// Create a decryption cipher instance from type, key, and IV.
    fn new_decrypt(cipher: SsrCipher, key: &[u8], iv: &[u8]) -> Self {
        use cipher::KeyIvInit;

        match cipher {
            SsrCipher::None => CipherInstance::None,
            SsrCipher::Aes128Cfb => {
                let dec = cfb_mode::BufDecryptor::<aes::Aes128>::new_from_slices(key, iv)
                    .expect("aes-128-cfb: invalid key/iv length");
                CipherInstance::Aes128CfbDec(dec)
            }
            SsrCipher::Aes256Cfb => {
                let dec = cfb_mode::BufDecryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .expect("aes-256-cfb: invalid key/iv length");
                CipherInstance::Aes256CfbDec(dec)
            }
            SsrCipher::ChaCha20Ietf => {
                // ChaCha20 is symmetric — encrypt and decrypt are the same XOR operation.
                let c = chacha20::ChaCha20::new_from_slices(key, iv)
                    .expect("chacha20-ietf: invalid key/iv length");
                CipherInstance::ChaCha20Ietf(c)
            }
            SsrCipher::Rc4Md5 => {
                let derived_key = rc4_md5_key(key, iv);
                CipherInstance::Rc4(Rc4State::new(&derived_key))
            }
        }
    }

    /// Encrypt/decrypt data in-place.
    fn apply(&mut self, data: &mut [u8]) {
        use cipher::StreamCipher;

        match self {
            CipherInstance::None => {} // passthrough
            CipherInstance::Aes128CfbEnc(enc) => {
                enc.encrypt(data);
            }
            CipherInstance::Aes256CfbEnc(enc) => {
                enc.encrypt(data);
            }
            CipherInstance::Aes128CfbDec(dec) => {
                dec.decrypt(data);
            }
            CipherInstance::Aes256CfbDec(dec) => {
                dec.decrypt(data);
            }
            CipherInstance::ChaCha20Ietf(c) => {
                c.apply_keystream(data);
            }
            CipherInstance::Rc4(rc4) => {
                rc4.apply(data);
            }
        }
    }
}

/// Derive the RC4 key by hashing (key || iv) with MD5.
fn rc4_md5_key(key: &[u8], iv: &[u8]) -> Vec<u8> {
    use digest::Digest;
    let mut hasher = md5::Md5::new();
    hasher.update(key);
    hasher.update(iv);
    hasher.finalize().to_vec() // 16 bytes
}

/// Minimal RC4 implementation (256-byte S-box).
struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

/// SSR stream cipher wrapper.
///
/// On the write path:
///   1. First write sends the randomly-generated IV, then encrypts data.
///   2. Subsequent writes encrypt data in-place and pass through.
///
/// On the read path:
///   1. First read receives the server's IV (iv_len bytes).
///   2. Subsequent reads decrypt data in-place.
pub struct SsrStream<T> {
    inner: T,
    cipher_type: SsrCipher,
    key: Vec<u8>,

    // Write (encrypt) state
    enc_cipher: Option<CipherInstance>,
    enc_iv: Vec<u8>,
    iv_sent: bool,
    write_flush_buf: Option<(Vec<u8>, usize)>,

    // Read (decrypt) state
    dec_cipher: Option<CipherInstance>,
    iv_buf: Vec<u8>, // accumulates incoming IV bytes
    iv_received: bool,
}

impl<T: Unpin> Unpin for SsrStream<T> {}

impl<T> SsrStream<T> {
    /// Create a new SSR stream wrapping the given inner stream.
    ///
    /// `key` is derived from the password via `evp_bytes_to_key`.
    pub fn new(inner: T, cipher: SsrCipher, password: &str) -> Self {
        let key = if cipher == SsrCipher::None {
            Vec::new()
        } else {
            evp_bytes_to_key(password.as_bytes(), cipher.key_len())
        };

        // Generate random IV for the encryption direction.
        let enc_iv = generate_iv(cipher.iv_len());
        let enc_cipher = if cipher == SsrCipher::None {
            Some(CipherInstance::None)
        } else {
            Some(CipherInstance::new_encrypt(cipher, &key, &enc_iv))
        };

        Self {
            inner,
            cipher_type: cipher,
            key,
            enc_cipher,
            enc_iv,
            iv_sent: cipher == SsrCipher::None, // no IV to send for "none"
            write_flush_buf: None,
            dec_cipher: if cipher == SsrCipher::None {
                Some(CipherInstance::None)
            } else {
                None
            },
            iv_buf: Vec::new(),
            iv_received: cipher == SsrCipher::None, // no IV to receive for "none"
        }
    }

    /// Derive the master key for external use (protocol plugins may need it).
    #[allow(dead_code)]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Generate a random IV of the given length.
fn generate_iv(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut iv = vec![0u8; len];
    if len > 0 {
        rand::thread_rng().fill_bytes(&mut iv);
    }
    iv
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for SsrStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Read the server's IV if we haven't yet.
        if !this.iv_received {
            let iv_len = this.cipher_type.iv_len();
            while this.iv_buf.len() < iv_len {
                let remaining = iv_len - this.iv_buf.len();
                let mut tmp = vec![0u8; remaining];
                let mut read_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ssr: connection closed while reading IV",
                            )));
                        }
                        this.iv_buf.extend_from_slice(read_buf.filled());
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Initialize the decryption cipher with the received IV.
            this.dec_cipher = Some(CipherInstance::new_decrypt(
                this.cipher_type,
                &this.key,
                &this.iv_buf,
            ));
            this.iv_received = true;
        }

        // Read encrypted data from inner, decrypt in-place.
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let n = after - before;
                if n > 0 {
                    if let Some(ref mut dec) = this.dec_cipher {
                        // Decrypt the newly read bytes in-place within the ReadBuf.
                        // Safety: we're modifying bytes we just read, which are within
                        // the filled portion of the buffer.
                        let filled = buf.filled_mut();
                        dec.apply(&mut filled[before..after]);
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for SsrStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Flush any pending buffered data first.
        while let Some((ref buf, ref mut pos)) = this.write_flush_buf {
            if *pos < buf.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "ssr: write zero",
                            )));
                        }
                        *pos += n;
                        if *pos >= buf.len() {
                            break;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                break;
            }
        }
        this.write_flush_buf = None;

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // First write: prepend IV.
        if !this.iv_sent {
            let mut out = Vec::with_capacity(this.enc_iv.len() + data.len());
            out.extend_from_slice(&this.enc_iv);

            // Encrypt the data
            let mut encrypted = data.to_vec();
            if let Some(ref mut enc) = this.enc_cipher {
                enc.apply(&mut encrypted);
            }
            out.extend_from_slice(&encrypted);

            this.iv_sent = true;

            let data_len = data.len();
            match Pin::new(&mut this.inner).poll_write(cx, &out) {
                Poll::Ready(Ok(n)) => {
                    if n < out.len() {
                        this.write_flush_buf = Some((out, n));
                    }
                    Poll::Ready(Ok(data_len))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.write_flush_buf = Some((out, 0));
                    Poll::Ready(Ok(data_len))
                }
            }
        } else {
            // Subsequent writes: encrypt in-place.
            let mut encrypted = data.to_vec();
            if let Some(ref mut enc) = this.enc_cipher {
                enc.apply(&mut encrypted);
            }

            let data_len = data.len();
            match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
                Poll::Ready(Ok(n)) => {
                    if n < encrypted.len() {
                        this.write_flush_buf = Some((encrypted, n));
                    }
                    Poll::Ready(Ok(data_len))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.write_flush_buf = Some((encrypted, 0));
                    Poll::Ready(Ok(data_len))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Flush pending data first.
        if let Some((ref buf, ref mut pos)) = this.write_flush_buf {
            while *pos < buf.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &buf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "ssr: write zero during flush",
                            )));
                        }
                        *pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        this.write_flush_buf = None;

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Best-effort flush before shutdown.
        if let Some((ref buf, ref mut pos)) = this.write_flush_buf {
            while *pos < buf.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &buf[*pos..]) {
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
        this.write_flush_buf = None;

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_from_name() {
        assert_eq!(
            SsrCipher::from_name("aes-256-cfb"),
            Some(SsrCipher::Aes256Cfb)
        );
        assert_eq!(
            SsrCipher::from_name("aes-128-cfb"),
            Some(SsrCipher::Aes128Cfb)
        );
        assert_eq!(
            SsrCipher::from_name("chacha20-ietf"),
            Some(SsrCipher::ChaCha20Ietf)
        );
        assert_eq!(SsrCipher::from_name("rc4-md5"), Some(SsrCipher::Rc4Md5));
        assert_eq!(SsrCipher::from_name("none"), Some(SsrCipher::None));
        assert_eq!(SsrCipher::from_name("unknown"), None);
    }

    #[test]
    fn cipher_key_iv_lengths() {
        assert_eq!(SsrCipher::Aes256Cfb.key_len(), 32);
        assert_eq!(SsrCipher::Aes256Cfb.iv_len(), 16);
        assert_eq!(SsrCipher::Aes128Cfb.key_len(), 16);
        assert_eq!(SsrCipher::Aes128Cfb.iv_len(), 16);
        assert_eq!(SsrCipher::ChaCha20Ietf.key_len(), 32);
        assert_eq!(SsrCipher::ChaCha20Ietf.iv_len(), 12);
        assert_eq!(SsrCipher::Rc4Md5.key_len(), 16);
        assert_eq!(SsrCipher::Rc4Md5.iv_len(), 16);
        assert_eq!(SsrCipher::None.key_len(), 0);
        assert_eq!(SsrCipher::None.iv_len(), 0);
    }

    #[test]
    fn evp_bytes_to_key_works() {
        let key = evp_bytes_to_key(b"password", 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn rc4_encrypt_decrypt() {
        let key = b"test-key-12345";
        let plaintext = b"Hello, world! This is a test of RC4 encryption.";

        let mut data = plaintext.to_vec();
        let mut rc4 = Rc4State::new(key);
        rc4.apply(&mut data);
        assert_ne!(&data, plaintext);

        // Decrypt (apply again with a fresh cipher)
        let mut rc4_dec = Rc4State::new(key);
        rc4_dec.apply(&mut data);
        assert_eq!(&data, plaintext);
    }

    #[test]
    fn aes_cfb_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = b"AES-256-CFB test data for SSR stream cipher";

        let mut data = plaintext.to_vec();
        let mut enc = CipherInstance::new_encrypt(SsrCipher::Aes256Cfb, &key, &iv);
        enc.apply(&mut data);
        assert_ne!(&data[..], &plaintext[..]);

        let mut dec = CipherInstance::new_decrypt(SsrCipher::Aes256Cfb, &key, &iv);
        dec.apply(&mut data);
        assert_eq!(&data[..], &plaintext[..]);
    }

    #[test]
    fn chacha20_ietf_encrypt_decrypt() {
        let key = [0xABu8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"ChaCha20-IETF test data for SSR";

        let mut data = plaintext.to_vec();
        let mut enc = CipherInstance::new_encrypt(SsrCipher::ChaCha20Ietf, &key, &iv);
        enc.apply(&mut data);
        assert_ne!(&data[..], &plaintext[..]);

        let mut dec = CipherInstance::new_decrypt(SsrCipher::ChaCha20Ietf, &key, &iv);
        dec.apply(&mut data);
        assert_eq!(&data[..], &plaintext[..]);
    }

    #[test]
    fn none_cipher_passthrough() {
        let plaintext = b"this should not change";
        let mut data = plaintext.to_vec();
        let mut enc = CipherInstance::new_encrypt(SsrCipher::None, &[], &[]);
        enc.apply(&mut data);
        assert_eq!(&data[..], &plaintext[..]);
    }

    #[test]
    fn rc4_md5_key_derivation() {
        let key = b"password";
        let iv = [0x01u8; 16];
        let derived = rc4_md5_key(key, &iv);
        assert_eq!(derived.len(), 16);

        // Different IV should give different key.
        let iv2 = [0x02u8; 16];
        let derived2 = rc4_md5_key(key, &iv2);
        assert_ne!(derived, derived2);
    }
}
