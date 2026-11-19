//! The TLS 1.3 client REALITY runs over.
//!
//! mihomo hands REALITY's ClientHello to uTLS, a fork of Go's `crypto/tls`.
//! rustls cannot send a hello it did not build, so this is the part of that
//! stack a REALITY client needs, written against RFC 8446 and following
//! `crypto/tls` wherever its choices show on the wire: the dummy
//! ChangeCipherSpec, the record sizes of early application data, how ignored
//! records and KeyUpdate are treated.
//!
//! Scope is what a REALITY server (itself a `crypto/tls` fork) can negotiate:
//! TLS 1.3, X25519 or X25519MLKEM768, the three TLS 1.3 AEAD suites. A
//! HelloRetryRequest or a TLS 1.2 ServerHello is an error here.

use anyhow::{anyhow, bail, Result};
use ring::{aead, digest, hkdf, hmac};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::cert::{self, Peer};
use super::hello::{ClientHello, HelloKeys, TLS13, X25519, X25519MLKEM768};
use crate::transport::x25519mlkem768;

const RECORD_HEADER_LEN: usize = 5;
/// Go `maxPlaintext`.
const MAX_PLAINTEXT: usize = 16384;
/// Go `maxCiphertextTLS13`.
const MAX_CIPHERTEXT: usize = 16384 + 256;
/// Go `maxHandshake`.
const MAX_HANDSHAKE: usize = 65536;
/// Go `maxUselessRecords`: consecutive records that carry nothing.
const MAX_USELESS_RECORDS: u32 = 32;
/// Go `tcpMSSEstimate` and `recordSizeBoostThreshold`.
const TCP_MSS_ESTIMATE: usize = 1208;
const RECORD_SIZE_BOOST_THRESHOLD: u64 = 128 * 1024;
const AEAD_TAG_LEN: usize = 16;

const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;

const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;
const KEY_UPDATE: u8 = 24;
const COMPRESSED_CERTIFICATE: u8 = 25;

const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_BAD_RECORD_MAC: u8 = 20;
const ALERT_RECORD_OVERFLOW: u8 = 22;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_DECODE_ERROR: u8 = 50;
const ALERT_DECRYPT_ERROR: u8 = 51;
const ALERT_PROTOCOL_VERSION: u8 = 70;
const ALERT_USER_CANCELED: u8 = 90;

/// SHA-256("HelloRetryRequest"): the random of a HelloRetryRequest.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The error a handshake fails with, and the TLS alert to send first — none
/// when the peer is already gone or sent an alert of its own.
struct Fatal {
    alert: Option<u8>,
    error: anyhow::Error,
}

fn fatal(alert: u8, message: impl Into<String>) -> Fatal {
    Fatal {
        alert: Some(alert),
        error: anyhow!(message.into()),
    }
}

impl From<io::Error> for Fatal {
    fn from(error: io::Error) -> Self {
        Self {
            alert: None,
            error: anyhow::Error::new(error),
        }
    }
}

/// A TLS 1.3 cipher suite.
#[derive(Clone, Copy)]
struct Suite {
    aead: &'static aead::Algorithm,
    hkdf: hkdf::Algorithm,
    hmac: hmac::Algorithm,
    digest: &'static digest::Algorithm,
}

impl Suite {
    fn by_id(id: u16) -> Option<Self> {
        let (aead, sha384) = match id {
            0x1301 => (&aead::AES_128_GCM, false),
            0x1302 => (&aead::AES_256_GCM, true),
            0x1303 => (&aead::CHACHA20_POLY1305, false),
            _ => return None,
        };
        Some(if sha384 {
            Self {
                aead,
                hkdf: hkdf::HKDF_SHA384,
                hmac: hmac::HMAC_SHA384,
                digest: &digest::SHA384,
            }
        } else {
            Self {
                aead,
                hkdf: hkdf::HKDF_SHA256,
                hmac: hmac::HMAC_SHA256,
                digest: &digest::SHA256,
            }
        })
    }

    fn hash_len(&self) -> usize {
        self.digest.output_len()
    }

    /// HKDF-Extract.
    fn extract(&self, salt: &[u8], secret: &[u8]) -> hkdf::Prk {
        hkdf::Salt::new(self.hkdf, salt).extract(secret)
    }

    /// HKDF-Expand-Label (RFC 8446, Section 7.1).
    fn expand_label(&self, prk: &hkdf::Prk, label: &str, context: &[u8], len: usize) -> Vec<u8> {
        struct Len(usize);
        impl hkdf::KeyType for Len {
            fn len(&self) -> usize {
                self.0
            }
        }
        let head = [(len >> 8) as u8, len as u8, (6 + label.len()) as u8];
        let context_len = [context.len() as u8];
        let info: [&[u8]; 5] = [&head, b"tls13 ", label.as_bytes(), &context_len, context];
        let mut out = vec![0u8; len];
        prk.expand(&info, Len(len))
            .and_then(|okm| okm.fill(&mut out))
            .expect("TLS 1.3 label outputs are far below the HKDF limit");
        out
    }

    /// HKDF-Expand-Label keyed with a traffic secret.
    fn expand_secret(&self, secret: &[u8], label: &str, len: usize) -> Vec<u8> {
        let prk = hkdf::Prk::new_less_safe(self.hkdf, secret);
        self.expand_label(&prk, label, &[], len)
    }

    /// The key of the Finished MAC, derived from a traffic secret.
    fn finished_key(&self, secret: &[u8]) -> hmac::Key {
        let key = self.expand_secret(secret, "finished", self.hash_len());
        hmac::Key::new(self.hmac, &key)
    }
}

/// The running handshake hash.
struct Transcript(digest::Context);

impl Transcript {
    fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    fn hash(&self) -> digest::Digest {
        self.0.clone().finish()
    }
}

/// One direction's record protection.
struct Cipher {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    sequence: u64,
}

impl Cipher {
    fn new(suite: &Suite, secret: &[u8]) -> Self {
        let key = suite.expand_secret(secret, "key", suite.aead.key_len());
        let iv = suite.expand_secret(secret, "iv", 12);
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(suite.aead, &key).expect("key length matches the suite"),
            ),
            iv: iv.try_into().expect("IV is 12 bytes"),
            sequence: 0,
        }
    }

    fn next_nonce(&mut self) -> aead::Nonce {
        let mut nonce = self.iv;
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        self.sequence += 1;
        aead::Nonce::assume_unique_for_key(nonce)
    }

    /// Append one protected record carrying `payload` as `content_type`.
    fn seal(&mut self, content_type: u8, payload: &[u8], out: &mut Vec<u8>) {
        let len = payload.len() + 1 + AEAD_TAG_LEN;
        let header = [APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
        out.extend_from_slice(&header);
        let start = out.len();
        out.extend_from_slice(payload);
        out.push(content_type);
        let nonce = self.next_nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(header), &mut out[start..])
            .expect("a record is far below the AEAD's length limit");
        out.extend_from_slice(tag.as_ref());
    }

    /// Open a protected record in place, returning its content type and the
    /// length of its plaintext, which starts at the front of `body`.
    fn open(&mut self, header: [u8; RECORD_HEADER_LEN], body: &mut [u8]) -> Option<(u8, usize)> {
        let nonce = self.next_nonce();
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(header), body)
            .ok()?;
        // RFC 8446, Section 5.4: the content type is the last non-zero byte.
        let end = plain.iter().rposition(|&byte| byte != 0)?;
        Some((plain[end], end))
    }
}

/// Go `maxPayloadSizeForWrite`: early application data goes out in records
/// that fit one TCP segment, growing by one segment per record, until 128 KiB
/// have been written.
fn max_payload_for_write(bytes_sent: u64, packets_sent: &mut u64) -> usize {
    if bytes_sent >= RECORD_SIZE_BOOST_THRESHOLD {
        return MAX_PLAINTEXT;
    }
    // TLS overhead: record header, AEAD tag, encrypted content type.
    let payload = TCP_MSS_ESTIMATE - RECORD_HEADER_LEN - AEAD_TAG_LEN - 1;
    let packet = *packets_sent;
    *packets_sent += 1;
    if packet > 1000 {
        return MAX_PLAINTEXT;
    }
    (payload * (packet as usize + 1)).min(MAX_PLAINTEXT)
}

/// Split a complete record off the front of `raw`, if one has arrived.
fn take_record(raw: &mut Vec<u8>) -> io::Result<Option<([u8; RECORD_HEADER_LEN], Vec<u8>)>> {
    if raw.len() < RECORD_HEADER_LEN {
        return Ok(None);
    }
    let header: [u8; RECORD_HEADER_LEN] = raw[..RECORD_HEADER_LEN].try_into().unwrap();
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tls: oversized record received with length {len}"),
        ));
    }
    if raw.len() < RECORD_HEADER_LEN + len {
        return Ok(None);
    }
    let body = raw[RECORD_HEADER_LEN..RECORD_HEADER_LEN + len].to_vec();
    raw.drain(..RECORD_HEADER_LEN + len);
    Ok(Some((header, body)))
}

/// Split a complete handshake message off the front of `buffer`.
fn take_handshake(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
    if len > MAX_HANDSHAKE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tls: handshake message of length {len} bytes exceeds maximum of {MAX_HANDSHAKE} bytes"),
        ));
    }
    if buffer.len() < 4 + len {
        return Ok(None);
    }
    Ok(Some(buffer.drain(..4 + len).collect()))
}

/// A cursor over a handshake message body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|bytes| u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize)
    }

    /// A vector behind a length prefix of `prefix_len` bytes.
    fn vector(&mut self, prefix_len: usize) -> Option<&'a [u8]> {
        let len = match prefix_len {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            _ => self.u24()?,
        };
        self.take(len)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What the handshake needs from a ServerHello.
struct ServerHello {
    suite_id: u16,
    group: u16,
    share: Vec<u8>,
}

/// mihomo compat: uTLS `checkServerHelloOrHRR` and `processServerHello`,
/// with the same alerts.
fn parse_server_hello(body: &[u8], hello: &ClientHello) -> Result<ServerHello, Fatal> {
    let malformed = || fatal(ALERT_DECODE_ERROR, "tls: malformed ServerHello");
    let mut reader = Reader(body);
    let version = reader.u16().ok_or_else(malformed)?;
    let random = reader.take(32).ok_or_else(malformed)?;
    let session_id = reader.vector(1).ok_or_else(malformed)?;
    let suite_id = reader.u16().ok_or_else(malformed)?;
    let compression = reader.u8().ok_or_else(malformed)?;

    let mut supported_version = 0;
    let mut share = None;
    if !reader.is_empty() {
        let mut extensions = Reader(reader.vector(2).ok_or_else(malformed)?);
        while !extensions.is_empty() {
            let kind = extensions.u16().ok_or_else(malformed)?;
            let mut data = Reader(extensions.vector(2).ok_or_else(malformed)?);
            match kind {
                43 => supported_version = data.u16().ok_or_else(malformed)?,
                51 => {
                    let group = data.u16().ok_or_else(malformed)?;
                    // A HelloRetryRequest names a group and carries no key.
                    let key = if data.is_empty() {
                        Vec::new()
                    } else {
                        data.vector(2).ok_or_else(malformed)?.to_vec()
                    };
                    share = Some((group, key));
                }
                _ => {}
            }
        }
    }

    if supported_version == 0 {
        // Not a TLS 1.3 ServerHello. uTLS would carry on in TLS 1.2 with
        // whatever answered; that cannot be a REALITY server.
        return Err(fatal(
            ALERT_PROTOCOL_VERSION,
            "tls: server selected an unsupported protocol version",
        ));
    }
    if supported_version != TLS13 {
        return Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server selected an invalid version after a HelloRetryRequest",
        ));
    }
    if version != 0x0303 {
        return Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server sent an incorrect legacy version",
        ));
    }
    if session_id != &hello.raw[super::hello::SESSION_ID] {
        return Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server did not echo the legacy session ID",
        ));
    }
    if compression != 0 {
        return Err(fatal(
            ALERT_DECODE_ERROR,
            "tls: server sent non-zero legacy TLS compression method",
        ));
    }
    if !hello.suites.contains(&suite_id) {
        return Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server chose an unconfigured cipher suite",
        ));
    }
    if random == HELLO_RETRY_REQUEST_RANDOM {
        return Err(fatal(
            ALERT_UNEXPECTED_MESSAGE,
            "tls: server sent a HelloRetryRequest, which REALITY cannot follow",
        ));
    }
    let Some((group, share)) = share else {
        return Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server did not send a key share",
        ));
    };
    if !hello.share_groups.contains(&group) {
        return Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server selected unsupported group",
        ));
    }
    Ok(ServerHello {
        suite_id,
        group,
        share,
    })
}

/// The (EC)DHE shared secret for the group the server chose.
fn shared_secret(keys: &HelloKeys, server: &ServerHello) -> Result<Vec<u8>, Fatal> {
    let invalid = |what: &str| {
        fatal(
            ALERT_ILLEGAL_PARAMETER,
            format!("tls: invalid server {what} key share"),
        )
    };
    match server.group {
        X25519 => {
            let secret = keys.ecdhe.as_ref().ok_or_else(|| invalid("X25519"))?;
            x25519mlkem768::x25519(secret, &server.share)
                .map(|shared| shared.to_vec())
                .map_err(|_| invalid("X25519"))
        }
        X25519MLKEM768 => keys
            .hybrid
            .as_ref()
            .ok_or_else(|| invalid("X25519MLKEM768"))?
            .complete(&server.share)
            .map(|shared| shared.to_vec())
            .map_err(|_| invalid("X25519MLKEM768")),
        // Offered for the fingerprint only (P-256, the Kyber draft group).
        _ => Err(fatal(
            ALERT_ILLEGAL_PARAMETER,
            "tls: server selected unsupported group",
        )),
    }
}

/// What the server's certificate must satisfy.
pub(super) struct Verify<'a> {
    /// REALITY's auth key: a certificate it signs is the proxy server's.
    pub auth_key: &'a [u8; 32],
    /// The camouflage name any other certificate has to be valid for.
    pub server_name: &'a str,
    pub now: std::time::SystemTime,
}

/// A completed handshake.
pub(super) struct Established<S> {
    pub stream: RealityStream<S>,
    /// Whose certificate the server presented.
    pub peer: Peer,
    /// The key exchange group the server selected.
    pub group: u16,
}

/// The connection while it handshakes: record framing over `io`.
struct Handshaking<S> {
    io: S,
    /// Transport bytes not yet forming a full record.
    raw: Vec<u8>,
    /// Handshake bytes not yet forming a full message.
    messages: Vec<u8>,
    read: Option<Cipher>,
    write: Option<Cipher>,
    /// Go `c.buffering`: the client's second flight leaves in one write.
    outgoing: Vec<u8>,
    /// Version on unprotected records: TLS 1.0 until a ServerHello arrives.
    record_version: u16,
    bytes_sent: u64,
    useless_records: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Handshaking<S> {
    /// Queue `payload` as one or more records of `content_type`.
    fn queue(&mut self, content_type: u8, payload: &[u8]) {
        for chunk in payload.chunks(MAX_PLAINTEXT) {
            match self.write.as_mut() {
                Some(cipher) => cipher.seal(content_type, chunk, &mut self.outgoing),
                None => {
                    self.outgoing.push(content_type);
                    self.outgoing
                        .extend_from_slice(&self.record_version.to_be_bytes());
                    self.outgoing
                        .extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                    self.outgoing.extend_from_slice(chunk);
                }
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.io.write_all(&self.outgoing).await?;
        self.io.flush().await?;
        self.bytes_sent += self.outgoing.len() as u64;
        self.outgoing.clear();
        Ok(())
    }

    /// Best effort: tell the peer why the handshake is being abandoned.
    ///
    /// Go flushes what the handshake had buffered (the dummy
    /// ChangeCipherSpec) together with the alert.
    async fn abort(mut self, fatal: Fatal) -> anyhow::Error {
        if let Some(alert) = fatal.alert {
            self.queue(ALERT, &[2, alert]);
        }
        let _ = self.flush().await;
        fatal.error
    }

    /// The next record's content type and plaintext, skipping what TLS 1.3
    /// ignores during a handshake.
    async fn read_record(&mut self) -> Result<(u8, Vec<u8>), Fatal> {
        loop {
            let record = take_record(&mut self.raw)
                .map_err(|error| fatal(ALERT_RECORD_OVERFLOW, error.to_string()))?;
            let Some((header, mut body)) = record else {
                let mut chunk = [0u8; 4096];
                let read = self.io.read(&mut chunk).await?;
                if read == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                self.raw.extend_from_slice(&chunk[..read]);
                continue;
            };

            let (content_type, len) = match (header[0], self.read.as_mut()) {
                // RFC 8446, Appendix D.4: change_cipher_spec is dropped
                // without being decrypted.
                (CHANGE_CIPHER_SPEC, _) => {
                    if body != [1] {
                        return Err(fatal(ALERT_DECODE_ERROR, "tls: malformed ChangeCipherSpec"));
                    }
                    self.useless_records += 1;
                    if self.useless_records > MAX_USELESS_RECORDS {
                        return Err(fatal(
                            ALERT_UNEXPECTED_MESSAGE,
                            "tls: too many ignored records",
                        ));
                    }
                    continue;
                }
                (APPLICATION_DATA, Some(cipher)) => cipher
                    .open(header, &mut body)
                    .ok_or_else(|| fatal(ALERT_BAD_RECORD_MAC, "tls: bad record MAC"))?,
                (_, Some(_)) => {
                    return Err(fatal(
                        ALERT_UNEXPECTED_MESSAGE,
                        "tls: unexpected unprotected record",
                    ))
                }
                (content_type, None) => (content_type, body.len()),
            };
            body.truncate(len);
            if content_type == ALERT {
                let description = body.get(1).copied().unwrap_or(0);
                return Err(Fatal {
                    alert: None,
                    error: anyhow!("remote error: tls: alert({description})"),
                });
            }
            return Ok((content_type, body));
        }
    }

    /// The next handshake message, header included.
    async fn read_message(&mut self) -> Result<Vec<u8>, Fatal> {
        loop {
            let message = take_handshake(&mut self.messages)
                .map_err(|error| fatal(ALERT_DECODE_ERROR, error.to_string()))?;
            if let Some(message) = message {
                self.useless_records = 0;
                return Ok(message);
            }
            let (content_type, body) = self.read_record().await?;
            if content_type != HANDSHAKE {
                return Err(fatal(
                    ALERT_UNEXPECTED_MESSAGE,
                    format!("tls: unexpected record of type {content_type} during the handshake"),
                ));
            }
            self.messages.extend_from_slice(&body);
        }
    }
}

/// A handshake message: type, 24-bit length, body.
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(body);
    message
}

/// Run the handshake `hello` opens. `hello.raw` already carries the session
/// ID REALITY sealed into it.
pub(super) async fn connect<S>(
    io: S,
    hello: ClientHello,
    verify: Verify<'_>,
) -> Result<Established<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = Handshaking {
        io,
        raw: Vec::new(),
        messages: Vec::new(),
        read: None,
        write: None,
        outgoing: Vec::new(),
        // Go: the first ClientHello goes out in a TLS 1.0 record, for servers
        // that reject anything newer there.
        record_version: 0x0301,
        bytes_sent: 0,
        useless_records: 0,
    };
    conn.queue(HANDSHAKE, &hello.raw);
    conn.flush().await?;

    match handshake(&mut conn, &hello, &verify).await {
        Ok((secrets, outcome)) => {
            let Handshaking {
                io,
                raw,
                messages,
                bytes_sent,
                ..
            } = conn;
            // Go: a handshake message may not straddle the key change.
            if !messages.is_empty() {
                bail!("tls: unexpected handshake data after the server Finished");
            }
            Ok(Established {
                stream: RealityStream::new(io, secrets, raw, bytes_sent),
                peer: outcome.peer,
                group: outcome.group,
            })
        }
        Err(fatal) => Err(conn.abort(fatal).await),
    }
}

/// The application traffic secrets a finished handshake leaves behind.
struct Secrets {
    suite: Suite,
    client: Vec<u8>,
    server: Vec<u8>,
}

struct Outcome {
    peer: Peer,
    group: u16,
}

async fn handshake<S>(
    conn: &mut Handshaking<S>,
    hello: &ClientHello,
    verify: &Verify<'_>,
) -> Result<(Secrets, Outcome), Fatal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let unexpected = |got: u8, wanted: &str| {
        fatal(
            ALERT_UNEXPECTED_MESSAGE,
            format!("tls: received unexpected handshake message of type {got} when waiting for {wanted}"),
        )
    };

    let server_hello = conn.read_message().await?;
    if server_hello[0] != SERVER_HELLO {
        return Err(unexpected(server_hello[0], "ServerHello"));
    }
    conn.record_version = 0x0303;
    let server = parse_server_hello(&server_hello[4..], hello)?;
    let suite = Suite::by_id(server.suite_id).expect("checked against the offered suites");
    let mut transcript = Transcript(digest::Context::new(suite.digest));
    transcript.update(&hello.raw);
    transcript.update(&server_hello);

    // Go `sendDummyChangeCipherSpec`: middlebox compatibility, buffered until
    // the client Finished leaves with it.
    conn.queue(CHANGE_CIPHER_SPEC, &[1]);

    // RFC 8446, Section 7.1.
    let zeros = vec![0u8; suite.hash_len()];
    let empty_hash = digest::digest(suite.digest, &[]);
    let early_secret = suite.extract(&zeros, &zeros);
    let derived = suite.expand_label(
        &early_secret,
        "derived",
        empty_hash.as_ref(),
        suite.hash_len(),
    );
    let handshake_secret = suite.extract(&derived, &shared_secret(&hello.keys, &server)?);
    let hello_hash = transcript.hash();
    let secret = |label| {
        suite.expand_label(
            &handshake_secret,
            label,
            hello_hash.as_ref(),
            suite.hash_len(),
        )
    };
    let client_handshake_secret = secret("c hs traffic");
    let server_handshake_secret = secret("s hs traffic");
    // From here on both directions are protected, alerts included. The
    // ChangeCipherSpec queued above stays in the clear ahead of them.
    conn.read = Some(Cipher::new(&suite, &server_handshake_secret));
    conn.write = Some(Cipher::new(&suite, &client_handshake_secret));
    if !conn.messages.is_empty() {
        return Err(fatal(
            ALERT_UNEXPECTED_MESSAGE,
            "tls: handshake data after the ServerHello is not protected",
        ));
    }

    let encrypted_extensions = conn.read_message().await?;
    if encrypted_extensions[0] != ENCRYPTED_EXTENSIONS {
        return Err(unexpected(encrypted_extensions[0], "EncryptedExtensions"));
    }
    transcript.update(&encrypted_extensions);
    let alps = hello
        .alps
        .is_some_and(|code_point| has_extension(&encrypted_extensions[4..], code_point));

    let mut next = conn.read_message().await?;
    let mut certificate_request = None;
    if next[0] == CERTIFICATE_REQUEST {
        transcript.update(&next);
        // The request context is echoed in the client's Certificate.
        certificate_request = Some(
            Reader(&next[4..])
                .vector(1)
                .ok_or_else(|| fatal(ALERT_DECODE_ERROR, "tls: malformed CertificateRequest"))?
                .to_vec(),
        );
        next = conn.read_message().await?;
    }

    transcript.update(&next);
    let certificate_body = match next[0] {
        CERTIFICATE => next[4..].to_vec(),
        COMPRESSED_CERTIFICATE => cert::decompress(&next[4..])
            .map_err(|error| fatal(ALERT_BAD_CERTIFICATE, error.to_string()))?,
        other => return Err(unexpected(other, "Certificate")),
    };
    let certificates = parse_certificates(&certificate_body)?;
    let peer = cert::verify_chain(
        &certificates,
        verify.auth_key,
        verify.server_name,
        verify.now,
    )
    .map_err(|error| fatal(ALERT_BAD_CERTIFICATE, error.to_string()))?;

    let certificate_verify = conn.read_message().await?;
    if certificate_verify[0] != CERTIFICATE_VERIFY {
        return Err(unexpected(certificate_verify[0], "CertificateVerify"));
    }
    let mut reader = Reader(&certificate_verify[4..]);
    let (Some(scheme), Some(signature)) = (reader.u16(), reader.vector(2)) else {
        return Err(fatal(
            ALERT_DECODE_ERROR,
            "tls: malformed CertificateVerify",
        ));
    };
    // RFC 8446, Section 4.4.3.
    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(transcript.hash().as_ref());
    cert::verify_signature(&certificates[0], scheme, &signed, signature).map_err(|error| {
        fatal(
            ALERT_DECRYPT_ERROR,
            format!("tls: invalid signature by the server certificate: {error}"),
        )
    })?;
    transcript.update(&certificate_verify);

    let finished = conn.read_message().await?;
    if finished[0] != FINISHED {
        return Err(unexpected(finished[0], "Finished"));
    }
    let finished_key = suite.finished_key(&server_handshake_secret);
    if hmac::verify(&finished_key, transcript.hash().as_ref(), &finished[4..]).is_err() {
        return Err(fatal(
            ALERT_DECRYPT_ERROR,
            "tls: invalid server finished hash",
        ));
    }
    transcript.update(&finished);

    let derived = suite.expand_label(
        &handshake_secret,
        "derived",
        empty_hash.as_ref(),
        suite.hash_len(),
    );
    let master_secret = suite.extract(&derived, &zeros);
    let finished_hash = transcript.hash();
    let secret = |label| {
        suite.expand_label(
            &master_secret,
            label,
            finished_hash.as_ref(),
            suite.hash_len(),
        )
    };
    let secrets = Secrets {
        suite,
        client: secret("c ap traffic"),
        server: secret("s ap traffic"),
    };

    if alps {
        // uTLS `sendClientEncryptedExtensions`: a client that negotiated ALPS
        // sends its own (empty) settings.
        let code_point = hello.alps.expect("set when the server accepted ALPS");
        let mut extensions = code_point.to_be_bytes().to_vec();
        extensions.extend_from_slice(&[0, 0]);
        let mut body = (extensions.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&extensions);
        let client_extensions = message(ENCRYPTED_EXTENSIONS, &body);
        transcript.update(&client_extensions);
        conn.queue(HANDSHAKE, &client_extensions);
    }
    if let Some(request_context) = certificate_request {
        // No client certificate is configured: an empty list.
        let mut body = vec![request_context.len() as u8];
        body.extend_from_slice(&request_context);
        body.extend_from_slice(&[0, 0, 0]);
        let certificate = message(CERTIFICATE, &body);
        transcript.update(&certificate);
        conn.queue(HANDSHAKE, &certificate);
    }
    let client_finished = message(
        FINISHED,
        hmac::sign(
            &suite.finished_key(&client_handshake_secret),
            transcript.hash().as_ref(),
        )
        .as_ref(),
    );
    conn.queue(HANDSHAKE, &client_finished);
    conn.flush().await?;

    Ok((
        secrets,
        Outcome {
            peer,
            group: server.group,
        },
    ))
}

/// Whether an extension block (a u16-prefixed list) contains `kind`.
fn has_extension(body: &[u8], kind: u16) -> bool {
    let Some(extensions) = Reader(body).vector(2) else {
        return false;
    };
    let mut extensions = Reader(extensions);
    while let (Some(found), Some(_)) = (extensions.u16(), extensions.vector(2)) {
        if found == kind {
            return true;
        }
    }
    false
}

/// The DER certificates of a Certificate message body, leaf first.
fn parse_certificates(body: &[u8]) -> Result<Vec<Vec<u8>>, Fatal> {
    let malformed = || fatal(ALERT_DECODE_ERROR, "tls: malformed Certificate");
    let mut reader = Reader(body);
    reader.vector(1).ok_or_else(malformed)?; // request context
    let mut list = Reader(reader.vector(3).ok_or_else(malformed)?);
    let mut certificates = Vec::new();
    while !list.is_empty() {
        certificates.push(list.vector(3).ok_or_else(malformed)?.to_vec());
        list.vector(2).ok_or_else(malformed)?; // extensions
    }
    if certificates.is_empty() {
        return Err(fatal(
            ALERT_DECODE_ERROR,
            "tls: received empty certificates message",
        ));
    }
    Ok(certificates)
}

/// An established REALITY connection: TLS 1.3 application data over `S`.
pub struct RealityStream<S> {
    io: S,
    suite: Suite,

    read: Cipher,
    read_secret: Vec<u8>,
    /// Transport bytes not yet forming a full record.
    raw: Vec<u8>,
    /// Application data not yet handed to the reader.
    plain: Vec<u8>,
    plain_at: usize,
    /// Post-handshake handshake bytes not yet forming a full message.
    messages: Vec<u8>,
    /// Go `retryCount`: consecutive records that advanced nothing.
    useless_records: u32,
    eof: bool,

    write: Cipher,
    write_secret: Vec<u8>,
    /// Protected records not yet accepted by the transport.
    outgoing: Vec<u8>,
    outgoing_at: usize,
    /// Go `bytesSent` / `packetsSent`, which size early records.
    bytes_sent: u64,
    packets_sent: u64,
    close_notify_sent: bool,
}

impl<S> RealityStream<S> {
    fn new(io: S, secrets: Secrets, raw: Vec<u8>, bytes_sent: u64) -> Self {
        Self {
            io,
            suite: secrets.suite,
            read: Cipher::new(&secrets.suite, &secrets.server),
            read_secret: secrets.server,
            raw,
            plain: Vec::new(),
            plain_at: 0,
            messages: Vec::new(),
            useless_records: 0,
            eof: false,
            write: Cipher::new(&secrets.suite, &secrets.client),
            write_secret: secrets.client,
            outgoing: Vec::new(),
            outgoing_at: 0,
            bytes_sent,
            packets_sent: 0,
            close_notify_sent: false,
        }
    }

    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.into())
    }

    /// Go `retryReadRecord`: a record that carried nothing.
    fn useless_record(&mut self) -> io::Result<()> {
        self.useless_records += 1;
        if self.useless_records > MAX_USELESS_RECORDS {
            return Err(Self::invalid("tls: too many ignored records"));
        }
        Ok(())
    }

    /// Take in one record's worth of plaintext.
    fn process_record(
        &mut self,
        header: [u8; RECORD_HEADER_LEN],
        mut body: Vec<u8>,
    ) -> io::Result<()> {
        if header[0] == CHANGE_CIPHER_SPEC {
            // RFC 8446, Appendix D.4: ignored without being decrypted.
            if body != [1] {
                return Err(Self::invalid("tls: malformed ChangeCipherSpec"));
            }
            return self.useless_record();
        }
        if header[0] != APPLICATION_DATA {
            return Err(Self::invalid("tls: unexpected unprotected record"));
        }
        let (content_type, len) = self
            .read
            .open(header, &mut body)
            .ok_or_else(|| Self::invalid("tls: bad record MAC"))?;
        body.truncate(len);

        match content_type {
            APPLICATION_DATA => {
                if body.is_empty() {
                    // REALITY servers pad the handshake with empty records.
                    return self.useless_record();
                }
                if !self.messages.is_empty() {
                    return Err(Self::invalid(
                        "tls: application data inside a handshake message",
                    ));
                }
                self.useless_records = 0;
                if self.plain_at == self.plain.len() {
                    self.plain = body;
                    self.plain_at = 0;
                } else {
                    self.plain.extend_from_slice(&body);
                }
            }
            HANDSHAKE => {
                self.messages.extend_from_slice(&body);
                while let Some(message) = take_handshake(&mut self.messages)? {
                    // Go `handlePostHandshakeMessage`.
                    self.useless_record()?;
                    match message[0] {
                        NEW_SESSION_TICKET => {}
                        KEY_UPDATE => self.key_update(&message[4..])?,
                        other => {
                            return Err(Self::invalid(format!(
                                "tls: received unexpected handshake message of type {other}"
                            )))
                        }
                    }
                }
            }
            ALERT => match body.get(1).copied() {
                Some(ALERT_CLOSE_NOTIFY) => self.eof = true,
                // Go: some implementations send this ahead of close_notify.
                Some(ALERT_USER_CANCELED) => self.useless_record()?,
                description => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!(
                            "remote error: tls: alert({})",
                            description.unwrap_or_default()
                        ),
                    ))
                }
            },
            other => {
                return Err(Self::invalid(format!(
                    "tls: unexpected record of type {other}"
                )))
            }
        }
        Ok(())
    }

    /// Go `handleKeyUpdate`: answer a requested update, then roll the read key.
    fn key_update(&mut self, body: &[u8]) -> io::Result<()> {
        let update_requested = match body {
            [0] => false,
            [1] => true,
            _ => return Err(Self::invalid("tls: malformed KeyUpdate")),
        };
        let next = |suite: &Suite, secret: &[u8]| {
            suite.expand_secret(secret, "traffic upd", suite.hash_len())
        };
        if update_requested && !self.close_notify_sent {
            // The answer goes out under the old key, ahead of anything
            // written later; `poll_write` and `poll_flush` push it out.
            self.write
                .seal(HANDSHAKE, &message(KEY_UPDATE, &[0]), &mut self.outgoing);
            self.write_secret = next(&self.suite, &self.write_secret);
            self.write = Cipher::new(&self.suite, &self.write_secret);
        }
        self.read_secret = next(&self.suite, &self.read_secret);
        self.read = Cipher::new(&self.suite, &self.read_secret);
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> RealityStream<S> {
    /// Hand queued records to the transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.outgoing_at < self.outgoing.len() {
            let written =
                ready!(Pin::new(&mut self.io).poll_write(cx, &self.outgoing[self.outgoing_at..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.outgoing_at += written;
            self.bytes_sent += written as u64;
        }
        self.outgoing.clear();
        self.outgoing_at = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_at < this.plain.len() {
                let len = buf.remaining().min(this.plain.len() - this.plain_at);
                buf.put_slice(&this.plain[this.plain_at..this.plain_at + len]);
                this.plain_at += len;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if let Some((header, body)) = take_record(&mut this.raw)? {
                let queued = this.outgoing.len();
                this.process_record(header, body)?;
                if this.outgoing.len() > queued {
                    // A KeyUpdate answer was queued: start it on its way. A
                    // full transport is not this read's problem.
                    if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                continue;
            }

            let mut chunk = [0u8; 16 * 1024];
            let mut chunk = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut chunk))?;
            if chunk.filled().is_empty() {
                // Go: popular sites close without close_notify, so EOF is
                // accepted at a record boundary — and only there.
                if this.raw.is_empty() {
                    this.eof = true;
                    continue;
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.raw.extend_from_slice(chunk.filled());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.close_notify_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tls: protocol is shutdown",
            )));
        }
        // At most one record is ever buffered: the previous one has to be on
        // the wire before the next is accepted.
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(max_payload_for_write(
            this.bytes_sent,
            &mut this.packets_sent,
        ));
        this.write
            .seal(APPLICATION_DATA, &buf[..len], &mut this.outgoing);
        // The record is accepted either way; a full transport finishes it on
        // the next write or flush.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_notify_sent {
            // Go `closeNotify`: a warning-level close_notify alert.
            this.close_notify_sent = true;
            this.write
                .seal(ALERT, &[1, ALERT_CLOSE_NOTIFY], &mut this.outgoing);
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_records_grow_by_one_segment_each() {
        // Go `maxPayloadSizeForWrite` with a TLS 1.3 AEAD: 1208 - 5 - 16 - 1.
        let mut packets = 0;
        let sizes: Vec<usize> = (0..15)
            .map(|_| max_payload_for_write(2000, &mut packets))
            .collect();
        assert_eq!(&sizes[..4], [1186, 2372, 3558, 4744]);
        assert_eq!(sizes[12], 15418);
        assert_eq!(&sizes[13..], [MAX_PLAINTEXT, MAX_PLAINTEXT]);
        // Past the boost threshold every record may be full, and the packet
        // counter stops moving.
        assert_eq!(
            max_payload_for_write(RECORD_SIZE_BOOST_THRESHOLD, &mut packets),
            MAX_PLAINTEXT
        );
        assert_eq!(packets, 15);
    }

    #[test]
    fn expand_label_matches_rfc_8448() {
        // RFC 8448, Section 3: the "derived" secret of the early secret.
        let suite = Suite::by_id(0x1301).unwrap();
        let early = suite.extract(&[0u8; 32], &[0u8; 32]);
        let derived = suite.expand_label(
            &early,
            "derived",
            digest::digest(&digest::SHA256, &[]).as_ref(),
            32,
        );
        assert_eq!(
            hex::encode(derived),
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
        );
    }

    #[test]
    fn records_round_trip_and_reject_tampering() {
        let suite = Suite::by_id(0x1303).unwrap();
        let secret = [7u8; 32];
        let mut sealer = Cipher::new(&suite, &secret);
        let mut opener = Cipher::new(&suite, &secret);

        let mut wire = Vec::new();
        sealer.seal(APPLICATION_DATA, b"hello", &mut wire);
        sealer.seal(HANDSHAKE, b"", &mut wire);
        let (header, mut body) = take_record(&mut wire).unwrap().unwrap();
        assert_eq!(header[..3], [APPLICATION_DATA, 3, 3]);
        let (content_type, len) = opener.open(header, &mut body).unwrap();
        assert_eq!(
            (content_type, &body[..len]),
            (APPLICATION_DATA, &b"hello"[..])
        );
        let (header, mut body) = take_record(&mut wire).unwrap().unwrap();
        assert_eq!(opener.open(header, &mut body), Some((HANDSHAKE, 0)));
        assert!(wire.is_empty());

        sealer.seal(APPLICATION_DATA, b"again", &mut wire);
        let (header, mut body) = take_record(&mut wire).unwrap().unwrap();
        body[0] ^= 1;
        assert!(opener.open(header, &mut body).is_none());
    }

    #[test]
    fn record_and_message_framing_wait_for_complete_units() {
        let mut raw = vec![APPLICATION_DATA, 3, 3, 0, 3, 1, 2];
        assert!(take_record(&mut raw).unwrap().is_none());
        raw.push(3);
        let (_, body) = take_record(&mut raw).unwrap().unwrap();
        assert_eq!(body, [1, 2, 3]);
        // Go `maxCiphertextTLS13`.
        let mut oversized = vec![APPLICATION_DATA, 3, 3, 0x41, 0x01];
        assert!(take_record(&mut oversized).is_err());

        let mut messages = vec![KEY_UPDATE, 0, 0, 1];
        assert!(take_handshake(&mut messages).unwrap().is_none());
        messages.extend_from_slice(&[0, NEW_SESSION_TICKET]);
        assert_eq!(
            take_handshake(&mut messages).unwrap().unwrap(),
            [KEY_UPDATE, 0, 0, 1, 0]
        );
        assert_eq!(messages, [NEW_SESSION_TICKET]);
    }
}
