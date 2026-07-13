//! Snell outbound proxy handler.
//!
//! 1:1 behavioral clone of mihomo's `transport/snell` + `adapter/outbound/snell.go`.
//!
//! Wire protocol (v1/v2/v3):
//!   The TCP connection is wrapped in a shadowsocks-style AEAD layer
//!   (`shadowaead.NewConn`). The only differences from Shadowsocks AEAD are:
//!     * the per-session subkey is derived with **argon2id** (not HKDF-SHA1 /
//!       EVP_BytesToKey): `argon2.IDKey(psk, salt, 3, 8, 1, 32)[:keySize]`
//!     * salt size is fixed at 16 bytes
//!     * cipher: AES-128-GCM for version >= 2, ChaCha20-Poly1305 for version 1
//!   The chunk framing is identical: `[salt][enc_len(2)+tag][enc_payload+tag]...`
//!
//! Request header (written as the first payload *through* the AEAD layer):
//!   `[Version=1][command][clientID len=0][hostlen][host][port(2 BE)]`
//!   command = CommandConnectV2 (5) for version==2 or reuse, else CommandConnect (1).
//!
//! Reply (read from the decrypted stream before user data):
//!   1 byte command. CommandTunnel(0) => ok. CommandError(2) => 1-byte code,
//!   1-byte message length, message. Anything else => "command not support".
//!
//! v4/v5 (newV4Conn) and the `reuse` v2 session pool are NOT ported — see the
//! parity notes in the accompanying report.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

use super::{OutboundHandler, ProxyStream};
use crate::common::addr::Address;
use crate::config::proxy::ProxyConfig;
use crate::dns::DnsResolver;
use crate::proxy::shadowsocks::plugin::ObfsStream;
use crate::transport::tcp::{self, ConnectOpts};

// Snell protocol constants (mihomo transport/snell/snell.go).
const SNELL_VERSION1: u8 = 1;
const SNELL_VERSION2: u8 = 2;
const SNELL_VERSION3: u8 = 3;
const SNELL_VERSION4: u8 = 4;
const SNELL_VERSION5: u8 = 5;
const DEFAULT_SNELL_VERSION: u8 = SNELL_VERSION1;

/// The `Version` byte written at the head of every request (mihomo `Version byte = 1`).
const HEADER_VERSION: u8 = 1;

const COMMAND_CONNECT: u8 = 1;
const COMMAND_CONNECT_V2: u8 = 5;

const COMMAND_TUNNEL: u8 = 0;
const COMMAND_ERROR: u8 = 2;

/// Fixed AEAD parameters (mihomo compat: shadowaead framing).
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SALT_SIZE: usize = 16;
const MAX_PAYLOAD_SIZE: usize = 0x3FFF;

/// Snell KDF: `argon2.IDKey(psk, salt, time=3, memory=8 KiB, threads=1, keylen=32)[:key_size]`.
///
/// mihomo compat: cipher.go `snellKDF` uses argon2id with these exact parameters,
/// then truncates to the cipher's key size.
fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // time=3, memory=8 KiB, parallelism=1, output=32 bytes.
    let params = Params::new(8, 3, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(psk, salt, &mut out)
        .expect("argon2 hash");
    out[..key_size].to_vec()
}

/// The AEAD cipher selected by Snell version.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SnellCipher {
    /// AES-128-GCM, 16-byte key (version >= 2).
    Aes128Gcm,
    /// ChaCha20-Poly1305, 32-byte key (version 1).
    ChaCha20Poly1305,
}

impl SnellCipher {
    /// mihomo compat: `StreamConn` selects AES-128-GCM for version != 1, else ChaCha20.
    fn for_version(version: u8) -> Self {
        if version != SNELL_VERSION1 {
            SnellCipher::Aes128Gcm
        } else {
            SnellCipher::ChaCha20Poly1305
        }
    }

    fn key_size(&self) -> usize {
        match self {
            SnellCipher::Aes128Gcm => 16,
            SnellCipher::ChaCha20Poly1305 => 32,
        }
    }
}

/// A ready-to-use AEAD instance (key already expanded).
enum CachedCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20(Box<ChaCha20Poly1305>),
}

impl CachedCipher {
    fn new(cipher: SnellCipher, key: &[u8]) -> Self {
        match cipher {
            SnellCipher::Aes128Gcm => {
                CachedCipher::Aes128Gcm(Box::new(Aes128Gcm::new(GenericArray::from_slice(key))))
            }
            SnellCipher::ChaCha20Poly1305 => CachedCipher::ChaCha20(Box::new(
                ChaCha20Poly1305::new(GenericArray::from_slice(key)),
            )),
        }
    }

    fn encrypt_in_place(&self, nonce: &[u8; NONCE_LEN], data: &mut Vec<u8>) -> io::Result<()> {
        let n = GenericArray::from_slice(nonce);
        match self {
            CachedCipher::Aes128Gcm(c) => c
                .encrypt_in_place(n, b"", data)
                .map_err(|e| io::Error::other(format!("snell aes-128-gcm encrypt: {e}"))),
            CachedCipher::ChaCha20(c) => c
                .encrypt_in_place(n, b"", data)
                .map_err(|e| io::Error::other(format!("snell chacha20-poly1305 encrypt: {e}"))),
        }
    }

    fn decrypt_in_place(&self, nonce: &[u8; NONCE_LEN], data: &mut Vec<u8>) -> io::Result<()> {
        let n = GenericArray::from_slice(nonce);
        match self {
            CachedCipher::Aes128Gcm(c) => c.decrypt_in_place(n, b"", data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("snell aes-128-gcm decrypt: {e}"),
                )
            }),
            CachedCipher::ChaCha20(c) => c.decrypt_in_place(n, b"", data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("snell chacha20-poly1305 decrypt: {e}"),
                )
            }),
        }
    }
}

/// Little-endian incrementing nonce (mihomo `shadowaead.increment`).
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
        for byte in &mut self.counter {
            let (v, overflow) = byte.overflowing_add(1);
            *byte = v;
            if !overflow {
                break;
            }
        }
    }
}

/// Build the Snell request header (mihomo `WriteHeaderWithReuse`).
///
/// `[Version=1][command][clientID len=0][hostlen][host][port(2 BE)]`
fn build_header(host: &str, port: u16, version: u8, reuse: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + host.len());
    buf.push(HEADER_VERSION);
    if version == SNELL_VERSION2 || reuse {
        buf.push(COMMAND_CONNECT_V2);
    } else {
        buf.push(COMMAND_CONNECT);
    }
    // clientID length (always 0)
    buf.push(0);
    // host & port
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

enum WriteState {
    Ready,
    Flushing { buf: Vec<u8>, pos: usize },
}

enum ReadState {
    WaitingSalt { buf: Vec<u8> },
    WaitingLength { buf: Vec<u8> },
    WaitingPayload { buf: Vec<u8>, payload_len: usize },
    Buffered { buf: Vec<u8>, pos: usize },
}

pin_project! {
    /// Snell AEAD stream (shadowaead framing with argon2id-derived subkeys).
    ///
    /// The header is queued as the first encrypted chunk. On the read side the
    /// 1-byte reply command is consumed transparently before any user data
    /// (matching mihomo `Snell.Read` -> `ReadReply`).
    pub struct SnellStream<T> {
        #[pin]
        inner: T,
        cipher: SnellCipher,
        psk: Vec<u8>,

        // Encrypt (write) path
        enc_cipher: Option<CachedCipher>,
        enc_nonce: NonceCounter,
        write_state: WriteState,

        // Decrypt (read) path
        dec_cipher: Option<CachedCipher>,
        dec_nonce: NonceCounter,
        read_state: ReadState,
        // The 1-byte reply has not yet been consumed.
        reply_pending: bool,
    }
}

impl<T> SnellStream<T> {
    /// Create a Snell stream. `header` is the request header written as the
    /// first AEAD chunk. A fresh random salt is generated and sent first.
    fn new(inner: T, cipher: SnellCipher, psk: Vec<u8>, header: Vec<u8>) -> Self {
        let salt = generate_salt();
        let enc_subkey = snell_kdf(&psk, &salt, cipher.key_size());
        let enc_cipher = CachedCipher::new(cipher, &enc_subkey);

        let mut enc_nonce = NonceCounter::new();
        let buf = build_initial_buffer(&salt, &enc_cipher, &mut enc_nonce, &header);

        Self {
            inner,
            cipher,
            psk,
            enc_cipher: Some(enc_cipher),
            enc_nonce,
            write_state: WriteState::Flushing { buf, pos: 0 },
            dec_cipher: None,
            dec_nonce: NonceCounter::new(),
            read_state: ReadState::WaitingSalt { buf: Vec::new() },
            reply_pending: true,
        }
    }

    /// Flush the initial handshake (salt + header chunk) to the wire.
    ///
    /// mihomo compat: `WriteHeaderWithReuse` writes the header before returning
    /// from `StreamConnContext`; do the same so the server processes the
    /// CONNECT before the relay loop starts (avoids a split-stream deadlock).
    async fn flush_handshake(&mut self) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        if let WriteState::Flushing { buf, pos } =
            std::mem::replace(&mut self.write_state, WriteState::Ready)
        {
            if pos < buf.len() {
                self.inner.write_all(&buf[pos..]).await?;
                self.inner.flush().await?;
            }
        }
        Ok(())
    }
}

/// Generate a random 16-byte salt.
fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Build `[salt][enc_len(2)+tag][enc_payload+tag]...` for the initial payload.
fn build_initial_buffer(
    salt: &[u8],
    cipher: &CachedCipher,
    nonce: &mut NonceCounter,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(salt.len() + payload.len() + 64);
    buf.extend_from_slice(salt);

    let mut offset = 0;
    while offset < payload.len() {
        let chunk_len = std::cmp::min(MAX_PAYLOAD_SIZE, payload.len() - offset);
        let chunk = &payload[offset..offset + chunk_len];

        let mut len_buf = vec![(chunk_len >> 8) as u8, (chunk_len & 0xFF) as u8];
        cipher
            .encrypt_in_place(nonce.current(), &mut len_buf)
            .expect("encrypt length");
        nonce.increment();
        buf.extend_from_slice(&len_buf);

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

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for SnellStream<T> {
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
                    while salt_buf.len() < SALT_SIZE {
                        let mut tmp = [0u8; SALT_SIZE];
                        let remaining = SALT_SIZE - salt_buf.len();
                        let mut rb = ReadBuf::new(&mut tmp[..remaining]);
                        match me.inner.as_mut().poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "snell: connection closed while reading salt",
                                    )));
                                }
                                salt_buf.extend_from_slice(rb.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let dec_subkey = snell_kdf(me.psk, salt_buf, me.cipher.key_size());
                    *me.dec_cipher = Some(CachedCipher::new(*me.cipher, &dec_subkey));
                    *me.read_state = ReadState::WaitingLength { buf: Vec::new() };
                }

                ReadState::WaitingLength {
                    buf: ref mut len_buf,
                } => {
                    let need = 2 + TAG_LEN;
                    while len_buf.len() < need {
                        let mut tmp = [0u8; 2 + TAG_LEN];
                        let remaining = need - len_buf.len();
                        let mut rb = ReadBuf::new(&mut tmp[..remaining]);
                        match me.inner.as_mut().poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    if len_buf.is_empty() {
                                        return Poll::Ready(Ok(())); // clean EOF
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "snell: connection closed while reading length",
                                    )));
                                }
                                len_buf.extend_from_slice(rb.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let dec = me
                        .dec_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("snell: decryption cipher not ready"))?;
                    dec.decrypt_in_place(me.dec_nonce.current(), len_buf)?;
                    me.dec_nonce.increment();

                    let payload_len = ((len_buf[0] as usize) << 8) | (len_buf[1] as usize);
                    // mihomo compat: zero-length chunk == EOF (shadowaead.ErrZeroChunk).
                    if payload_len == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    if payload_len > MAX_PAYLOAD_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("snell: payload length {payload_len} exceeds maximum"),
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
                        let mut rb = ReadBuf::new(&mut tmp[..to_read]);
                        match me.inner.as_mut().poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "snell: connection closed while reading payload",
                                    )));
                                }
                                payload_buf.extend_from_slice(rb.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }

                    let dec = me
                        .dec_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("snell: decryption cipher not ready"))?;
                    dec.decrypt_in_place(me.dec_nonce.current(), payload_buf)?;
                    me.dec_nonce.increment();

                    let mut decrypted = std::mem::take(payload_buf);

                    // mihomo compat: `Snell.Read` consumes the 1-byte reply command
                    // before handing out user data. The reply rides in the decrypted
                    // stream (first byte of the first chunk).
                    if *me.reply_pending {
                        parse_reply(&decrypted)?;
                        *me.reply_pending = false;
                        if decrypted.len() == 1 {
                            // Only the reply byte in this chunk: read the next chunk.
                            *me.read_state = ReadState::WaitingLength { buf: Vec::new() };
                            continue;
                        }
                        // Drop the consumed reply byte.
                        decrypted.drain(..1);
                    }

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

/// Parse the Snell reply command from the decrypted stream head.
///
/// mihomo `ReadReply`: CommandTunnel(0) => ok. CommandError(2) => the caller
/// still needs the code + message which follow; here (unlike mihomo, which
/// reads them lazily) they are already present in `data` because the whole
/// error frame arrives in one AEAD chunk. Anything else => "command not support".
fn parse_reply(data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell: empty reply",
        ));
    }
    match data[0] {
        COMMAND_TUNNEL => Ok(()),
        COMMAND_ERROR => {
            // [cmd][errcode(1)][msglen(1)][msg]
            if data.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell: truncated error reply",
                ));
            }
            let errcode = data[1] as i32;
            let msg_len = data[2] as usize;
            let msg_end = 3 + msg_len;
            if data.len() < msg_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell: truncated error message",
                ));
            }
            let msg = String::from_utf8_lossy(&data[3..msg_end]);
            Err(io::Error::other(format!(
                "server reported code: {errcode}, message: {msg}"
            )))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snell: command not support ({other})"),
        )),
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for SnellStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut me = self.project();

        // Flush any pending handshake / partial write first.
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
                                "snell: write zero",
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

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let enc = me
            .enc_cipher
            .as_ref()
            .ok_or_else(|| io::Error::other("snell: encryption cipher not ready"))?;

        let chunk_len = std::cmp::min(MAX_PAYLOAD_SIZE, data.len());
        let chunk = &data[..chunk_len];

        let mut out = vec![(chunk_len >> 8) as u8, (chunk_len & 0xFF) as u8];
        enc.encrypt_in_place(me.enc_nonce.current(), &mut out)?;
        me.enc_nonce.increment();

        let mut payload_buf = chunk.to_vec();
        enc.encrypt_in_place(me.enc_nonce.current(), &mut payload_buf)?;
        me.enc_nonce.increment();
        out.extend_from_slice(&payload_buf);

        let mut pos = 0;
        while pos < out.len() {
            match me.inner.as_mut().poll_write(cx, &out[pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "snell: write zero",
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
                                "snell: write zero during flush",
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

/// Parsed obfs-opts (mihomo `simpleObfsOption`).
#[derive(Clone, Debug)]
struct ObfsOption {
    mode: String,
    host: String,
}

pub struct SnellOutbound {
    name: String,
    server: String,
    port: u16,
    psk: Vec<u8>,
    version: u8,
    /// Invariantly false: v2 (implicit reuse) and v4-with-reuse are rejected at load.
    reuse: bool,
    udp: bool,
    obfs: Option<ObfsOption>,
    cipher: SnellCipher,
    connect_opts: ConnectOpts,
}

impl SnellOutbound {
    pub fn from_config(config: &ProxyConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("snell missing server"))?
            .clone();
        let port = config.port.ok_or_else(|| anyhow!("snell missing port"))?;
        let psk = config
            .password
            .as_ref()
            .ok_or_else(|| anyhow!("snell missing psk"))?
            .as_bytes()
            .to_vec();
        let addr = format!("{server}:{port}");

        // obfs-opts: { mode, host } (mihomo compat: NOT flat obfs/obfs-host).
        // Default host "bing.com" (mihomo `simpleObfsOption{Host: "bing.com"}`).
        let obfs = match config.extra.get("obfs-opts") {
            Some(serde_yaml::Value::Mapping(map)) => {
                let get = |k: &str| -> Option<String> {
                    map.get(serde_yaml::Value::String(k.to_string()))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                };
                let mode = get("mode").unwrap_or_default();
                let host = get("host").unwrap_or_else(|| "bing.com".to_string());
                match mode.as_str() {
                    "" => None,
                    "tls" | "http" => Some(ObfsOption { mode, host }),
                    other => {
                        return Err(anyhow!("snell {addr} obfs mode error: {other}"));
                    }
                }
            }
            Some(_) => return Err(anyhow!("snell {addr} obfs-opts must be a map")),
            None => None,
        };

        // Version handling (mihomo `NewSnell`).
        let mut version = config
            .extra
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u8)
            .unwrap_or(0);
        if version == 0 {
            version = DEFAULT_SNELL_VERSION;
        }
        if version == SNELL_VERSION5 {
            // mihomo compat: Snell v5 servers are backward-compatible with v4 clients.
            version = SNELL_VERSION4;
        }

        let reuse_cfg = config
            .extra
            .get("reuse")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let reuse = version == SNELL_VERSION2 || (version == SNELL_VERSION4 && reuse_cfg);

        let udp = config.udp.unwrap_or(false);

        match version {
            SNELL_VERSION1 | SNELL_VERSION2 => {
                if udp {
                    return Err(anyhow!("snell version {version} not support UDP"));
                }
            }
            SNELL_VERSION3 => {}
            SNELL_VERSION4 => {
                // mihomo compat: v4/v5 use newV4Conn framing, which is not ported here.
                return Err(anyhow!(
                    "snell {addr}: version {version} (v4/v5) not supported yet"
                ));
            }
            other => return Err(anyhow!("snell version error: {other}")),
        }

        if reuse {
            // mihomo compat: reuse uses a v2 session pool (transport/snell/pool.go),
            // not ported. Only v2 (always reuse) and v4-with-reuse trigger this;
            // v4 is already rejected above, so this only guards v2.
            return Err(anyhow!(
                "snell {addr}: session reuse (version 2 / reuse:true) not supported yet"
            ));
        }

        let cipher = SnellCipher::for_version(version);

        info!(
            "Snell proxy '{}': {}:{} version={} obfs={} udp={}",
            config.name,
            server,
            port,
            version,
            obfs.as_ref().map(|o| o.mode.as_str()).unwrap_or("none"),
            udp
        );

        Ok(Self {
            name: config.name.clone(),
            server,
            port,
            psk,
            version,
            reuse,
            udp,
            obfs,
            cipher,
            connect_opts: ConnectOpts::from_proxy_config(config),
        })
    }
}

#[async_trait]
impl OutboundHandler for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> &str {
        "Snell"
    }

    fn supports_udp(&self) -> bool {
        // v1/v2 reject UDP at load; v3 would support it but UDP relay is not
        // wired here (see parity notes). Report the config value for honesty.
        self.udp
    }

    async fn connect_stream(
        &self,
        target: &Address,
        dns: &DnsResolver,
    ) -> Result<Box<dyn ProxyStream>> {
        let ip = dns.resolve_proxy_server(&self.server).await?;
        let addr = std::net::SocketAddr::new(ip, self.port);
        let stream = tcp::connect(addr, &self.connect_opts).await?;
        debug!(
            "Snell v{} connected to {}:{}",
            self.version, self.server, self.port
        );

        // mihomo compat: the request header carries the destination as
        // `metadata.String()` (domain when present, else IP literal).
        let host = target.host();
        let port = target.port();
        let header = build_header(&host, port, self.version, self.reuse);

        // Apply obfs (simple-obfs) *before* the AEAD layer, matching
        // mihomo `snellStreamConn`.
        match &self.obfs {
            Some(o) if o.mode == "tls" => {
                self.wrap_snell(ObfsStream::new_tls(stream, o.host.clone()), header)
                    .await
            }
            Some(o) if o.mode == "http" => {
                self.wrap_snell(ObfsStream::new_http(stream, o.host.clone()), header)
                    .await
            }
            _ => self.wrap_snell(stream, header).await,
        }
    }
}

impl SnellOutbound {
    /// Wrap a transport stream in the Snell AEAD layer and flush the handshake.
    async fn wrap_snell<S>(&self, stream: S, header: Vec<u8>) -> Result<Box<dyn ProxyStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut ss = SnellStream::new(stream, self.cipher, self.psk.clone(), header);
        ss.flush_handshake().await?;
        Ok(Box::new(ss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_kdf_matches_reference() {
        // mihomo compat: argon2.IDKey(psk, salt, 3, 8, 1, 32)[:key_size].
        // Compute the reference independently via the argon2 crate and assert
        // snell_kdf agrees for both cipher key sizes.
        let psk = b"my-secret-psk";
        let salt = [0x11u8; SALT_SIZE];

        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(8, 3, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut reference = [0u8; 32];
        argon2
            .hash_password_into(psk, &salt, &mut reference)
            .unwrap();

        // 32-byte key (ChaCha20, version 1)
        let k32 = snell_kdf(psk, &salt, 32);
        assert_eq!(k32.len(), 32);
        assert_eq!(&k32[..], &reference[..]);

        // 16-byte key (AES-128-GCM, version >= 2) is a prefix of the full output
        let k16 = snell_kdf(psk, &salt, 16);
        assert_eq!(k16.len(), 16);
        assert_eq!(&k16[..], &reference[..16]);

        // Different salt -> different key
        let salt2 = [0x22u8; SALT_SIZE];
        let other = snell_kdf(psk, &salt2, 32);
        assert_ne!(k32, other);
    }

    #[test]
    fn cipher_selection_by_version() {
        assert_eq!(SnellCipher::for_version(1), SnellCipher::ChaCha20Poly1305);
        assert_eq!(SnellCipher::for_version(2), SnellCipher::Aes128Gcm);
        assert_eq!(SnellCipher::for_version(3), SnellCipher::Aes128Gcm);
        assert_eq!(SnellCipher::for_version(4), SnellCipher::Aes128Gcm);
        assert_eq!(SnellCipher::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(SnellCipher::Aes128Gcm.key_size(), 16);
    }

    #[test]
    fn header_encoding_connect() {
        // version 1, no reuse -> CommandConnect
        let h = build_header("example.com", 443, 1, false);
        // [Version=1][cmd=1][clientID=0][hostlen=11]["example.com"][port BE]
        assert_eq!(h[0], HEADER_VERSION);
        assert_eq!(h[1], COMMAND_CONNECT);
        assert_eq!(h[2], 0);
        assert_eq!(h[3], 11);
        assert_eq!(&h[4..15], b"example.com");
        assert_eq!(&h[15..17], &443u16.to_be_bytes());
        assert_eq!(h.len(), 17);
    }

    #[test]
    fn header_encoding_connect_v2_for_version2() {
        let h = build_header("a.com", 80, 2, false);
        assert_eq!(h[1], COMMAND_CONNECT_V2);
    }

    #[test]
    fn header_encoding_connect_v2_for_reuse() {
        let h = build_header("a.com", 80, 4, true);
        assert_eq!(h[1], COMMAND_CONNECT_V2);
    }

    #[test]
    fn reply_tunnel_ok() {
        assert!(parse_reply(&[COMMAND_TUNNEL]).is_ok());
        // trailing data after the tunnel byte is fine
        assert!(parse_reply(&[COMMAND_TUNNEL, 0xAB, 0xCD]).is_ok());
    }

    #[test]
    fn reply_error_with_message() {
        // [cmd=2][code=7]["oops"] -> len=4
        let mut frame = vec![COMMAND_ERROR, 7, 4];
        frame.extend_from_slice(b"oops");
        let err = parse_reply(&frame).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("code: 7"), "got: {s}");
        assert!(s.contains("message: oops"), "got: {s}");
    }

    #[test]
    fn reply_unknown_command() {
        let err = parse_reply(&[0x7F]).unwrap_err();
        assert!(err.to_string().contains("command not support"));
    }

    #[test]
    fn reply_error_truncated() {
        // cmd=2 but no code/len bytes
        assert!(parse_reply(&[COMMAND_ERROR]).is_err());
        // has code+len but message shorter than declared
        assert!(parse_reply(&[COMMAND_ERROR, 1, 10, b'x']).is_err());
    }

    #[test]
    fn initial_buffer_roundtrips_header_through_aead() {
        // Encrypt a header with a fresh salt, then decrypt it back using a
        // second cipher derived from the same salt+psk (as the server would).
        let psk = b"psk-abc";
        let salt = generate_salt();
        let cipher = SnellCipher::ChaCha20Poly1305;
        let subkey = snell_kdf(psk, &salt, cipher.key_size());
        let enc = CachedCipher::new(cipher, &subkey);
        let mut nonce = NonceCounter::new();

        let header = build_header("example.org", 8443, 1, false);
        let buf = build_initial_buffer(&salt, &enc, &mut nonce, &header);

        // starts with the salt
        assert_eq!(&buf[..SALT_SIZE], &salt[..]);

        // decrypt length (nonce 0) then payload (nonce 1)
        let dec = CachedCipher::new(cipher, &subkey);
        let mut dn = NonceCounter::new();
        let mut len_chunk = buf[SALT_SIZE..SALT_SIZE + 2 + TAG_LEN].to_vec();
        dec.decrypt_in_place(dn.current(), &mut len_chunk).unwrap();
        dn.increment();
        let plen = ((len_chunk[0] as usize) << 8) | (len_chunk[1] as usize);
        assert_eq!(plen, header.len());

        let start = SALT_SIZE + 2 + TAG_LEN;
        let mut payload = buf[start..start + plen + TAG_LEN].to_vec();
        dec.decrypt_in_place(dn.current(), &mut payload).unwrap();
        assert_eq!(&payload, &header);
    }
}
