//! Shadowsocks stream ciphers, and the unencrypted `none` method.
//!
//! mihomo compat: sing-shadowsocks2 `shadowstream/method.go` and
//! `cipher/method_none.go`. Each direction of a connection, and every UDP
//! packet, is `[salt][keystream XOR payload]`; what the client sends starts
//! with the target address. `none` is that framing with no salt and no
//! keystream.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use cipher::generic_array::GenericArray;
use cipher::{BlockCipher, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use digest::Digest;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead::generate_salt;

/// Most plaintext one write takes: what the transport does not accept at once
/// is held encrypted until the next write or flush.
const WRITE_CHUNK_SIZE: usize = 16 * 1024;

/// The stream ciphers sing-shadowsocks2 registers, and `none`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCipher {
    None,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Rc4Md5,
    ChaCha20Ietf,
    XChaCha20,
    ChaCha20,
}

/// Which way a keystream runs — it only matters to CFB, whose feedback is the
/// ciphertext (`encryptConstructor` / `decryptConstructor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Encrypt,
    Decrypt,
}

/// One direction of one salt's keystream, applied in place.
pub(super) type Keystream = Box<dyn FnMut(&mut [u8]) -> io::Result<()> + Send>;

impl StreamCipher {
    /// Parse cipher name from config string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "none" => Some(StreamCipher::None),
            "aes-128-ctr" => Some(StreamCipher::Aes128Ctr),
            "aes-192-ctr" => Some(StreamCipher::Aes192Ctr),
            "aes-256-ctr" => Some(StreamCipher::Aes256Ctr),
            "aes-128-cfb" => Some(StreamCipher::Aes128Cfb),
            "aes-192-cfb" => Some(StreamCipher::Aes192Cfb),
            "aes-256-cfb" => Some(StreamCipher::Aes256Cfb),
            "rc4-md5" => Some(StreamCipher::Rc4Md5),
            "chacha20-ietf" => Some(StreamCipher::ChaCha20Ietf),
            "xchacha20" => Some(StreamCipher::XChaCha20),
            "chacha20" => Some(StreamCipher::ChaCha20),
            _ => None,
        }
    }

    /// Key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            StreamCipher::None => 0,
            StreamCipher::Aes128Ctr | StreamCipher::Aes128Cfb | StreamCipher::Rc4Md5 => 16,
            StreamCipher::Aes192Ctr | StreamCipher::Aes192Cfb => 24,
            StreamCipher::Aes256Ctr
            | StreamCipher::Aes256Cfb
            | StreamCipher::ChaCha20Ietf
            | StreamCipher::XChaCha20
            | StreamCipher::ChaCha20 => 32,
        }
    }

    /// Salt (IV) length in bytes.
    pub fn salt_len(&self) -> usize {
        match self {
            StreamCipher::None => 0,
            StreamCipher::Aes128Ctr
            | StreamCipher::Aes192Ctr
            | StreamCipher::Aes256Ctr
            | StreamCipher::Aes128Cfb
            | StreamCipher::Aes192Cfb
            | StreamCipher::Aes256Cfb
            | StreamCipher::Rc4Md5 => 16,
            StreamCipher::ChaCha20Ietf => 12,
            StreamCipher::XChaCha20 => 24,
            StreamCipher::ChaCha20 => 8,
        }
    }

    /// The keystream for `key` and `salt`, whose lengths are this cipher's.
    pub(super) fn keystream(&self, key: &[u8], salt: &[u8], direction: Direction) -> Keystream {
        match self {
            StreamCipher::None => Box::new(|_| Ok(())),
            StreamCipher::Aes128Ctr => ctr::<aes::Aes128>(key, salt),
            StreamCipher::Aes192Ctr => ctr::<aes::Aes192>(key, salt),
            StreamCipher::Aes256Ctr => ctr::<aes::Aes256>(key, salt),
            StreamCipher::Aes128Cfb => cfb::<aes::Aes128>(key, salt, direction),
            StreamCipher::Aes192Cfb => cfb::<aes::Aes192>(key, salt, direction),
            StreamCipher::Aes256Cfb => cfb::<aes::Aes256>(key, salt, direction),
            StreamCipher::Rc4Md5 => {
                // The RC4 key is MD5(key || salt).
                let mut rc4 = Rc4::new(
                    &md5::Md5::new()
                        .chain_update(key)
                        .chain_update(salt)
                        .finalize(),
                );
                Box::new(move |data| {
                    rc4.apply(data);
                    Ok(())
                })
            }
            StreamCipher::ChaCha20Ietf => chacha::<chacha20::ChaCha20>(key, salt),
            StreamCipher::XChaCha20 => chacha::<chacha20::XChaCha20>(key, salt),
            StreamCipher::ChaCha20 => chacha::<chacha20::ChaCha20Legacy>(key, salt),
        }
    }
}

const KEY_IV_LEN: &str = "key and salt lengths are the cipher's";

/// AES-CTR as Go's `cipher.NewCTR`: the whole 16-byte IV is one big-endian
/// counter.
fn ctr<C>(key: &[u8], iv: &[u8]) -> Keystream
where
    C: BlockCipher + BlockEncrypt + KeyInit + Send + 'static,
{
    let cipher = C::new_from_slice(key).expect(KEY_IV_LEN);
    let mut counter = [0u8; 16];
    counter.copy_from_slice(iv);
    let mut block = [0u8; 16];
    let mut used = block.len();
    Box::new(move |data| {
        for byte in data {
            if used == block.len() {
                block = counter;
                cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
                for digit in counter.iter_mut().rev() {
                    *digit = digit.wrapping_add(1);
                    if *digit != 0 {
                        break;
                    }
                }
                used = 0;
            }
            *byte ^= block[used];
            used += 1;
        }
        Ok(())
    })
}

/// AES-CFB with full-block feedback, as Go's `cipher.NewCFBEncrypter` /
/// `NewCFBDecrypter`.
fn cfb<C>(key: &[u8], iv: &[u8], direction: Direction) -> Keystream
where
    C: BlockCipher + BlockEncryptMut + KeyInit + Send + 'static,
{
    match direction {
        Direction::Encrypt => {
            let mut cfb = cfb_mode::BufEncryptor::<C>::new_from_slices(key, iv).expect(KEY_IV_LEN);
            Box::new(move |data| {
                cfb.encrypt(data);
                Ok(())
            })
        }
        Direction::Decrypt => {
            let mut cfb = cfb_mode::BufDecryptor::<C>::new_from_slices(key, iv).expect(KEY_IV_LEN);
            Box::new(move |data| {
                cfb.decrypt(data);
                Ok(())
            })
        }
    }
}

/// ChaCha20 with an 8-byte (original), 12-byte (IETF) or 24-byte (XChaCha20)
/// nonce.
///
/// mihomo compat deviation: the `chacha20` crate counts blocks in 32 bits for
/// all three, so a single salt's keystream ends after 256 GiB with an error;
/// upstream's `NewChaCha20IgnoreCounterOverflow` keeps going.
fn chacha<C>(key: &[u8], nonce: &[u8]) -> Keystream
where
    C: KeyIvInit + cipher::StreamCipher + Send + 'static,
{
    let mut cipher = C::new_from_slices(key, nonce).expect(KEY_IV_LEN);
    Box::new(move |data| {
        cipher
            .try_apply_keystream(data)
            .map_err(|_| io::Error::other("chacha20 keystream exhausted"))
    })
}

/// RC4 keystream generator. Duplicated from `proxy/ssr/stream.rs`, whose copy
/// is private to that module.
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
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

pin_project! {
    /// A Shadowsocks connection under a stream cipher or `none`.
    ///
    /// Wire format, each direction: `[salt][keystream XOR bytes ...]`; the
    /// client's bytes start with the target address header.
    pub struct CipherStream<T> {
        #[pin]
        inner: T,
        cipher: StreamCipher,
        key: Vec<u8>,

        enc: Keystream,
        // Encrypted bytes the transport has not taken yet. It starts out as
        // the request — salt and address header — which the first
        // `poll_write` sends even when called with an empty buffer (see
        // `crate::proxy::Handshake`).
        pending: Vec<u8>,
        pending_pos: usize,

        // Set once the server's salt has arrived.
        dec: Option<Keystream>,
        salt: Vec<u8>,
    }
}

impl<T> CipherStream<T> {
    /// Wrap `inner`; `addr_header` is the target address the request names.
    pub fn new(
        inner: T,
        cipher: StreamCipher,
        key: Vec<u8>,
        addr_header: Vec<u8>,
    ) -> io::Result<Self> {
        let mut pending = generate_salt(cipher.salt_len());
        let salt_len = pending.len();
        pending.extend_from_slice(&addr_header);
        let (salt, header) = pending.split_at_mut(salt_len);
        let mut enc = cipher.keystream(&key, salt, Direction::Encrypt);
        enc(header)?;

        Ok(Self {
            inner,
            cipher,
            key,
            enc,
            pending,
            pending_pos: 0,
            dec: None,
            salt: Vec::new(),
        })
    }
}

/// Write `pending[*pos..]` out until the transport has taken all of it.
fn poll_drain<T: AsyncWrite>(
    mut inner: Pin<&mut T>,
    cx: &mut Context<'_>,
    pending: &[u8],
    pos: &mut usize,
) -> Poll<io::Result<()>> {
    while *pos < pending.len() {
        let n = ready!(inner.as_mut().poll_write(cx, &pending[*pos..]))?;
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        *pos += n;
    }
    Poll::Ready(Ok(()))
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for CipherStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut me = self.project();

        // The server's salt comes first.
        let salt_len = me.cipher.salt_len();
        while me.salt.len() < salt_len {
            let mut tmp = [0u8; 24];
            let mut salt_buf = ReadBuf::new(&mut tmp[..salt_len - me.salt.len()]);
            ready!(me.inner.as_mut().poll_read(cx, &mut salt_buf))?;
            if salt_buf.filled().is_empty() {
                if me.salt.is_empty() {
                    // Clean EOF - the server sent nothing at all
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed while reading salt",
                )));
            }
            me.salt.extend_from_slice(salt_buf.filled());
        }
        let dec = me
            .dec
            .get_or_insert_with(|| me.cipher.keystream(me.key, me.salt, Direction::Decrypt));

        let filled = buf.filled().len();
        ready!(me.inner.as_mut().poll_read(cx, buf))?;
        dec(&mut buf.filled_mut()[filled..])?;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for CipherStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut me = self.project();

        // Whatever is owed goes first: on the first write that is the
        // request, which leaves even when there is no data to follow it.
        ready!(poll_drain(
            me.inner.as_mut(),
            cx,
            me.pending,
            me.pending_pos
        ))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let len = data.len().min(WRITE_CHUNK_SIZE);
        me.pending.clear();
        *me.pending_pos = 0;
        me.pending.extend_from_slice(&data[..len]);
        if let Err(e) = (me.enc)(me.pending) {
            // Never leave plaintext where a later flush would send it.
            me.pending.clear();
            return Poll::Ready(Err(e));
        }

        // The keystream has moved past these bytes, so they are taken now;
        // what the transport refuses waits for the next write or flush.
        if let Poll::Ready(Err(e)) = poll_drain(me.inner.as_mut(), cx, me.pending, me.pending_pos) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut me = self.project();
        ready!(poll_drain(
            me.inner.as_mut(),
            cx,
            me.pending,
            me.pending_pos
        ))?;
        me.inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut me = self.project();
        ready!(poll_drain(
            me.inner.as_mut(),
            cx,
            me.pending,
            me.pending_pos
        ))?;
        me.inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::aead::encode_address;
    use super::*;
    use crate::common::addr::Address;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// Name, key length and salt length of everything sing-shadowsocks2's
    /// `shadowstream` registers, and of `none`.
    const CIPHERS: [(&str, StreamCipher, usize, usize); 11] = [
        ("none", StreamCipher::None, 0, 0),
        ("aes-128-ctr", StreamCipher::Aes128Ctr, 16, 16),
        ("aes-192-ctr", StreamCipher::Aes192Ctr, 24, 16),
        ("aes-256-ctr", StreamCipher::Aes256Ctr, 32, 16),
        ("aes-128-cfb", StreamCipher::Aes128Cfb, 16, 16),
        ("aes-192-cfb", StreamCipher::Aes192Cfb, 24, 16),
        ("aes-256-cfb", StreamCipher::Aes256Cfb, 32, 16),
        ("rc4-md5", StreamCipher::Rc4Md5, 16, 16),
        ("chacha20-ietf", StreamCipher::ChaCha20Ietf, 32, 12),
        ("xchacha20", StreamCipher::XChaCha20, 32, 24),
        ("chacha20", StreamCipher::ChaCha20, 32, 8),
    ];

    /// Name, key, salt and the ciphertext of [`plaintext`], from
    /// implementations independent of this crate: OpenSSL for AES-CTR,
    /// AES-CFB and ChaCha20, and for the rest RC4 and HChaCha20 written out
    /// from their specifications (checked against the published vectors).
    /// The CTR salt ends in ones, so its carry runs up the block.
    const VECTORS: [(&str, &str, &str, &str); 10] = [
        (
            "aes-128-ctr",
            "101112131415161718191a1b1c1d1e1f",
            "00112233445566ffffffffffffffffff",
            "ef183aedf50766bedff5bab4bd9b34862674409513c4a3b7e82003699024a3ce1dfb7e16d67bcc2c63\
             6c5ba4de9581da7099af304afe5d937dde347907c4e8712305f66ccfa2",
        ),
        (
            "aes-128-cfb",
            "101112131415161718191a1b1c1d1e1f",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "17b9c52ce4e9ee471542cf5db26fe54ccfedac580c0b1e782e61533b3b1c8386607e70251090fa655a\
             1f223376bdf4baea863de3744765f63510e2a62195f9072ea03e59cdfc",
        ),
        (
            "aes-192-ctr",
            "101112131415161718191a1b1c1d1e1f2021222324252627",
            "00112233445566ffffffffffffffffff",
            "67292ce94047e641a16bc27fa86a3b287d0f491c67293c9a209cd6cfb4927f3ecb302d7cc3a0a3eb4d\
             4a3b0d2552655455bd3f260bf9236e518b9d63a68b51c32a32e5ec3628",
        ),
        (
            "aes-192-cfb",
            "101112131415161718191a1b1c1d1e1f2021222324252627",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "cd8800f39e5ad87fa1b7f2d44c45f383d77086b922bb6e9b99a4b356406147d5584399da8dc81650cb\
             58f44dcbaab67d0edc5ab20c02bf45dc5e0c02953cdc2bc53aead3ea9b",
        ),
        (
            "aes-256-ctr",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "00112233445566ffffffffffffffffff",
            "24eb6d3c5d30da4e8fd5a532759a683520dc0910e0bb096e12290120b1cfcc32c3af8103c2aaa6fa47\
             5256b97034640613d30a23317987be4da789c358e6e6cf7cf4d6ab10c1",
        ),
        (
            "aes-256-cfb",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "527f5710da4286d3c5b5f00c72498f8d68c4ba943790606d45958cea5cb7db3c66f3a779e4e8d0df7e\
             1b5e3163ebbc9b39da119e2b16ea675292e727507d392e7f86ad35923e",
        ),
        (
            "rc4-md5",
            "101112131415161718191a1b1c1d1e1f",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "82de8d16960f8fbf39258e4a0175ec2585ddc523fb85c962226fc0af1efcfc72a81ee461e411dd7951\
             02af4ffe5ccc613b19d59148f15c319a0b3d544982c032702be862a9d1",
        ),
        (
            "chacha20-ietf",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "a0a1a2a3a4a5a6a7a8a9aaab",
            "2d5ca00c181ffe7eef6feeba4ddbf36ecb227ec213ce2d34816fa1b48312c21933edd851b49da10fd0\
             687dbd1f66ae7e0387cccaff237ad1447c2371581091a2d3960b828e01",
        ),
        (
            "xchacha20",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "720b074af15d53bb1a9bb972dd0f27d0bd02f63e5184c340ab38cb9efd9f6b817406b15d9ce49ac155\
             ac4d8dd909b56d91356b8c6d8111f30951710062513babafc4f9898302",
        ),
        (
            "chacha20",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "c0c1c2c3c4c5c6c7",
            "39868184c284c3f136b7e9b3199986e7cd26466005e6258ec86c07031900be016a64df6ea2b66444db\
             973741d286650a6addf4f36cac924e90af759dc00d57ce42d4a4a5d3a0",
        ),
    ];

    /// 70 bytes: more than one 64-byte ChaCha block and four AES blocks.
    fn plaintext() -> Vec<u8> {
        (0..70u32).map(|i| (7 * i + 3) as u8).collect()
    }

    fn target() -> Vec<u8> {
        encode_address(&Address::Domain("example.com".to_string(), 443))
    }

    /// What the client has put on the wire and the server has not read yet.
    async fn sent(server: &mut DuplexStream) -> Vec<u8> {
        let mut wire = vec![0u8; 1 << 16];
        let n = server.read(&mut wire).await.unwrap();
        wire.truncate(n);
        wire
    }

    #[test]
    fn cipher_names_keys_and_salts() {
        for (name, cipher, key_len, salt_len) in CIPHERS {
            assert_eq!(StreamCipher::from_name(name), Some(cipher));
            assert_eq!(cipher.key_len(), key_len, "{name}");
            assert_eq!(cipher.salt_len(), salt_len, "{name}");
        }
        // mihomo compat: the method registry knows `none` by that name alone.
        for name in ["plain", "dummy", "table", "aes-128-cfb8", "salsa20"] {
            assert_eq!(StreamCipher::from_name(name), None, "{name}");
        }
    }

    #[test]
    fn keystream_known_answers() {
        for (name, key, salt, ciphertext) in VECTORS {
            let cipher = StreamCipher::from_name(name).unwrap();
            let key = hex::decode(key).unwrap();
            let salt = hex::decode(salt).unwrap();
            assert_eq!(key.len(), cipher.key_len(), "{name}");
            assert_eq!(salt.len(), cipher.salt_len(), "{name}");

            let mut data = plaintext();
            cipher.keystream(&key, &salt, Direction::Encrypt)(&mut data).unwrap();
            assert_eq!(hex::encode(&data), ciphertext, "{name}");

            // Piecewise, as a connection applies it: the position carries on.
            let mut pieces = plaintext();
            let mut encrypt = cipher.keystream(&key, &salt, Direction::Encrypt);
            let mut rest = pieces.as_mut_slice();
            for len in [1, 15, 16, 17, 21] {
                let (piece, tail) = rest.split_at_mut(len);
                encrypt(piece).unwrap();
                rest = tail;
            }
            assert_eq!(pieces, data, "{name} piecewise");

            cipher.keystream(&key, &salt, Direction::Decrypt)(&mut data).unwrap();
            assert_eq!(data, plaintext(), "{name} decrypt");
        }
    }

    /// The request, the tunnel's empty writes around it, a server that speaks
    /// first, and the payload after — for every cipher and for `none`.
    #[tokio::test]
    async fn connection_framing() {
        for (name, cipher, key_len, salt_len) in CIPHERS {
            let key = vec![0x33u8; key_len];
            let (client_io, mut server) = tokio::io::duplex(1 << 16);
            let mut client = CipherStream::new(client_io, cipher, key.clone(), target()).unwrap();

            // An empty first write sends exactly the request: salt + address.
            assert_eq!(client.write(&[]).await.unwrap(), 0, "{name}");
            client.flush().await.unwrap();
            let wire = sent(&mut server).await;
            assert_eq!(wire.len(), salt_len + target().len(), "{name}");
            let (salt, header) = wire.split_at(salt_len);
            let mut decrypt = cipher.keystream(&key, salt, Direction::Decrypt);
            let mut header = header.to_vec();
            decrypt(&mut header).unwrap();
            assert_eq!(header, target(), "{name}");

            // The server speaks before the client has sent any payload.
            let server_salt = vec![0x77u8; salt_len];
            let mut encrypt = cipher.keystream(&key, &server_salt, Direction::Encrypt);
            let mut banner = b"220 ready\r\n".to_vec();
            encrypt(&mut banner).unwrap();
            server.write_all(&server_salt).await.unwrap();
            server.write_all(&banner).await.unwrap();
            let mut banner = [0u8; 11];
            client.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"220 ready\r\n", "{name}");

            // With the request out, an empty write is nothing at all, and the
            // payload carries on under the request's keystream.
            assert_eq!(client.write(&[]).await.unwrap(), 0, "{name}");
            client.write_all(b"payload").await.unwrap();
            client.flush().await.unwrap();
            let mut payload = sent(&mut server).await;
            assert_eq!(payload.len(), 7, "{name}");
            decrypt(&mut payload).unwrap();
            assert_eq!(payload, b"payload", "{name}");
        }
    }

    /// `none` puts the address and the data on the wire as they are.
    #[tokio::test]
    async fn none_is_plain_address_then_data() {
        let (client_io, mut server) = tokio::io::duplex(1 << 16);
        let mut client =
            CipherStream::new(client_io, StreamCipher::None, Vec::new(), target()).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        client.flush().await.unwrap();
        let mut expected = target();
        expected.extend_from_slice(b"GET / HTTP/1.1\r\n");
        assert_eq!(sent(&mut server).await, expected);

        server.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        let mut reply = [0u8; 17];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"HTTP/1.1 200 OK\r\n");
    }

    /// A transport that takes a few bytes at a time must still receive every
    /// byte once, in order: the keystream cannot be rewound.
    #[tokio::test]
    async fn slow_transport_loses_and_repeats_nothing() {
        let cipher = StreamCipher::Aes256Cfb;
        let key = vec![0x33u8; 32];
        let (client_io, mut server) = tokio::io::duplex(8);
        let mut client = CipherStream::new(client_io, cipher, key.clone(), target()).unwrap();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();

        let expected_len = cipher.salt_len() + target().len() + data.len();
        let reader = tokio::spawn(async move {
            let mut wire = vec![0u8; expected_len];
            server.read_exact(&mut wire).await.unwrap();
            wire
        });
        client.write_all(&data).await.unwrap();
        client.flush().await.unwrap();

        let wire = reader.await.unwrap();
        let (salt, body) = wire.split_at(cipher.salt_len());
        let mut body = body.to_vec();
        cipher.keystream(&key, salt, Direction::Decrypt)(&mut body).unwrap();
        let mut expected = target();
        expected.extend_from_slice(&data);
        assert!(body == expected);
    }

    #[tokio::test]
    async fn server_salt_may_arrive_in_pieces_or_not_at_all() {
        let cipher = StreamCipher::ChaCha20Ietf;
        let key = vec![0x33u8; 32];
        let salt = [0x77u8; 12];
        let mut reply = b"reply".to_vec();
        cipher.keystream(&key, &salt, Direction::Encrypt)(&mut reply).unwrap();

        let (client_io, mut server) = tokio::io::duplex(1 << 16);
        let mut client = CipherStream::new(client_io, cipher, key.clone(), target()).unwrap();
        let reading = tokio::spawn(async move {
            let mut plain = [0u8; 5];
            client.read_exact(&mut plain).await.unwrap();
            plain
        });
        server.write_all(&salt[..5]).await.unwrap();
        tokio::task::yield_now().await;
        server.write_all(&salt[5..]).await.unwrap();
        server.write_all(&reply).await.unwrap();
        assert_eq!(&reading.await.unwrap(), b"reply");

        // Closed before anything arrived: end of stream.
        let (client_io, server) = tokio::io::duplex(1 << 16);
        let mut client = CipherStream::new(client_io, cipher, key.clone(), target()).unwrap();
        drop(server);
        assert_eq!(client.read(&mut [0u8; 8]).await.unwrap(), 0);

        // Closed inside the salt: an error.
        let (client_io, mut server) = tokio::io::duplex(1 << 16);
        let mut client = CipherStream::new(client_io, cipher, key, target()).unwrap();
        server.write_all(&salt[..5]).await.unwrap();
        drop(server);
        let error = client.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
