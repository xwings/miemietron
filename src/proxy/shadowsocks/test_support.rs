//! The server's side of the Shadowsocks wire formats, for tests.
//!
//! Written from the server implementations — sing-shadowsocks
//! `shadowaead/service.go`, `shadowaead_2022/service.go` and
//! `service_multi.go` — against the cipher crates directly. Nothing in here is
//! shared with the client code under test.

use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes_gcm::aead::generic_array::typenum::Unsigned;
use aes_gcm::aead::{Aead, AeadCore, KeyInit};

pub const SESSION_SUBKEY: &str = "shadowsocks 2022 session subkey";
pub const IDENTITY_SUBKEY: &str = "shadowsocks 2022 identity subkey";

/// Seal a plaintext under a nonce.
type Seal = Box<dyn Fn(&[u8], &[u8]) -> Vec<u8> + Send>;
/// Open a sealed text under a nonce, if it authenticates.
type Open = Box<dyn Fn(&[u8], &[u8]) -> Option<Vec<u8>> + Send>;

/// One AEAD key under the cipher a method names.
pub struct Key {
    seal: Seal,
    open: Open,
    nonce_len: usize,
}

impl Key {
    pub fn new(method: &str, key: &[u8]) -> Self {
        fn make<C: Aead + KeyInit + Clone + Send + 'static>(key: &[u8]) -> Key {
            let sealer = C::new_from_slice(key).expect("key length");
            let opener = sealer.clone();
            Key {
                seal: Box::new(move |nonce, plain| sealer.encrypt(nonce.into(), plain).unwrap()),
                open: Box::new(move |nonce, sealed| opener.decrypt(nonce.into(), sealed).ok()),
                nonce_len: <C as AeadCore>::NonceSize::USIZE,
            }
        }
        match method {
            "aes-128-gcm" | "2022-blake3-aes-128-gcm" => make::<aes_gcm::Aes128Gcm>(key),
            "aes-192-gcm" => make::<aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>>(key),
            "aes-256-gcm" | "2022-blake3-aes-256-gcm" => make::<aes_gcm::Aes256Gcm>(key),
            "chacha20-ietf-poly1305" | "2022-blake3-chacha20-poly1305" => {
                make::<chacha20poly1305::ChaCha20Poly1305>(key)
            }
            "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => {
                make::<chacha20poly1305::XChaCha20Poly1305>(key)
            }
            _ => panic!("no AEAD for {method}"),
        }
    }

    pub fn seal(&self, nonce: &[u8], plain: &[u8]) -> Vec<u8> {
        (self.seal)(nonce, plain)
    }

    pub fn open(&self, nonce: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        (self.open)(nonce, sealed)
    }
}

/// A key used along a stream, where the nonce is a little-endian counter.
pub struct StreamKey {
    key: Key,
    counter: u128,
}

impl StreamKey {
    pub fn new(method: &str, key: &[u8]) -> Self {
        Self {
            key: Key::new(method, key),
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Vec<u8> {
        let mut nonce = self.counter.to_le_bytes().to_vec();
        nonce.resize(self.key.nonce_len, 0);
        self.counter += 1;
        nonce
    }

    pub fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        self.key.seal(&nonce, plain)
    }

    pub fn open(&mut self, sealed: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        self.key
            .open(&nonce, sealed)
            .expect("chunk authenticates under the next nonce")
    }

    /// `[length][payload]`, each sealed on its own.
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut wire = self.seal(&(payload.len() as u16).to_be_bytes());
        wire.extend(self.seal(payload));
        wire
    }

    /// Open every length-prefixed chunk in `wire` and join their payloads.
    pub fn open_chunks(&mut self, mut wire: &[u8]) -> Vec<u8> {
        let mut plain = Vec::new();
        while !wire.is_empty() {
            let length = self.open(&wire[..2 + 16]);
            let length = u16::from_be_bytes([length[0], length[1]]) as usize;
            plain.extend(self.open(&wire[18..18 + length + 16]));
            wire = &wire[18 + length + 16..];
        }
        plain
    }
}

/// Legacy AEAD subkey: HKDF-SHA1 with info "ss-subkey".
pub fn legacy_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    struct Len(usize);
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let mut subkey = vec![0u8; key.len()];
    ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(key)
        .expand(&[b"ss-subkey"], Len(key.len()))
        .unwrap()
        .fill(&mut subkey)
        .unwrap();
    subkey
}

/// SS2022 subkey: BLAKE3 derive_key over `key || salt`, as long as the key.
pub fn blake3_subkey(context: &str, key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut subkey = vec![0u8; key.len()];
    blake3::Hasher::new_derive_key(context)
        .update(key)
        .update(salt)
        .finalize_xof()
        .fill(&mut subkey);
    subkey
}

/// What an identity header holds: the start of the next PSK's BLAKE3 hash.
pub fn psk_hash(psk: &[u8]) -> [u8; 16] {
    blake3::hash(psk).as_bytes()[..16].try_into().unwrap()
}

pub fn aes_ecb_encrypt(key: &[u8], block: &[u8]) -> [u8; 16] {
    let mut block = aes::Block::clone_from_slice(block);
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .unwrap()
            .encrypt_block(&mut block),
        _ => aes::Aes256::new_from_slice(key)
            .unwrap()
            .encrypt_block(&mut block),
    }
    block.into()
}

pub fn aes_ecb_decrypt(key: &[u8], block: &[u8]) -> [u8; 16] {
    let mut block = aes::Block::clone_from_slice(block);
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .unwrap()
            .decrypt_block(&mut block),
        _ => aes::Aes256::new_from_slice(key)
            .unwrap()
            .decrypt_block(&mut block),
    }
    block.into()
}

/// Length of the SOCKS address at the start of `bytes`.
pub fn socks_addr_len(bytes: &[u8]) -> usize {
    match bytes[0] {
        1 => 1 + 4 + 2,
        3 => 2 + bytes[1] as usize + 2,
        4 => 1 + 16 + 2,
        atyp => panic!("address type {atyp}"),
    }
}

fn be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}

/// A SS2022 TCP request as the server sees it.
pub struct Request2022 {
    pub salt: Vec<u8>,
    pub timestamp: u64,
    /// SOCKS address bytes.
    pub target: Vec<u8>,
    pub padding_len: usize,
    /// The reader, positioned after the request header chunks.
    pub key: StreamKey,
    /// What followed the request header on the wire.
    pub rest: Vec<u8>,
}

/// Read a SS2022 request (`newConnection` / `NewConnection0`). `psks` is the
/// key list the client is configured with: every identity header must name
/// the next key, as each hop of the chain would check.
pub fn read_request_2022(method: &str, psks: &[&[u8]], wire: &[u8]) -> Request2022 {
    let key_len = psks[0].len();
    let (salt, mut wire) = wire.split_at(key_len);
    for hop in psks.windows(2) {
        let identity_subkey = blake3_subkey(IDENTITY_SUBKEY, hop[0], salt);
        assert_eq!(
            aes_ecb_decrypt(&identity_subkey, &wire[..16]),
            psk_hash(hop[1]),
            "identity header names the next PSK"
        );
        wire = &wire[16..];
    }

    let psk = psks.last().unwrap();
    let mut key = StreamKey::new(method, &blake3_subkey(SESSION_SUBKEY, psk, salt));
    let fixed = key.open(&wire[..1 + 8 + 2 + 16]);
    assert_eq!(fixed[0], 0, "header type: client");
    let length = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
    let variable = key.open(&wire[27..27 + length + 16]);
    let addr_len = socks_addr_len(&variable);
    let padding_len = u16::from_be_bytes([variable[addr_len], variable[addr_len + 1]]) as usize;
    assert_eq!(
        variable.len(),
        addr_len + 2 + padding_len,
        "nothing but address and padding in a request without payload"
    );
    Request2022 {
        salt: salt.to_vec(),
        timestamp: be_u64(&fixed[1..]),
        target: variable[..addr_len].to_vec(),
        padding_len,
        key,
        rest: wire[27 + length + 16..].to_vec(),
    }
}

/// Start a SS2022 response (`writeResponse`): the salt, the fixed header and
/// the first payload chunk. Returns the wire bytes and the writer for the
/// length-prefixed chunks that follow.
pub fn response_2022(
    method: &str,
    psk: &[u8],
    salt: &[u8],
    request_salt: &[u8],
    timestamp: u64,
    first_chunk: &[u8],
) -> (Vec<u8>, StreamKey) {
    let mut key = StreamKey::new(method, &blake3_subkey(SESSION_SUBKEY, psk, salt));
    let mut header = vec![1];
    header.extend(timestamp.to_be_bytes());
    header.extend(request_salt);
    header.extend((first_chunk.len() as u16).to_be_bytes());
    let mut wire = salt.to_vec();
    wire.extend(key.seal(&header));
    wire.extend(key.seal(first_chunk));
    (wire, key)
}

/// A client packet as a SS2022 UDP server sees it.
#[derive(Debug)]
pub struct ClientPacket {
    pub session_id: u64,
    pub packet_id: u64,
    pub timestamp: u64,
    pub padding_len: usize,
    /// SOCKS address bytes.
    pub target: Vec<u8>,
    pub data: Vec<u8>,
}

/// The server side of SS2022 UDP (`newPacket`, `serverPacketWriter`).
/// `psks` is the key list the client is configured with.
pub struct UdpServer2022 {
    method: &'static str,
    psks: Vec<Vec<u8>>,
    pub session_id: u64,
}

impl UdpServer2022 {
    pub fn new(method: &'static str, psks: &[&[u8]], session_id: u64) -> Self {
        Self {
            method,
            psks: psks.iter().map(|psk| psk.to_vec()).collect(),
            session_id,
        }
    }

    fn is_chacha(&self) -> bool {
        self.method == "2022-blake3-chacha20-poly1305"
    }

    fn psk(&self) -> &[u8] {
        self.psks.last().unwrap()
    }

    /// Open a client packet, checking every identity header on the way.
    pub fn open(&self, packet: &[u8]) -> ClientPacket {
        let body = if self.is_chacha() {
            Key::new("xchacha20-poly1305", self.psk())
                .open(&packet[..24], &packet[24..])
                .expect("packet authenticates")
        } else {
            let header = aes_ecb_decrypt(&self.psks[0], &packet[..16]);
            let mut rest = &packet[16..];
            for hop in self.psks.windows(2) {
                let mut identity = aes_ecb_decrypt(&hop[0], &rest[..16]);
                for (byte, mask) in identity.iter_mut().zip(header) {
                    *byte ^= mask;
                }
                assert_eq!(
                    identity,
                    psk_hash(&hop[1]),
                    "identity header names the next PSK"
                );
                rest = &rest[16..];
            }
            let session_key = blake3_subkey(SESSION_SUBKEY, self.psk(), &header[..8]);
            let mut body = header.to_vec();
            body.extend(
                Key::new(self.method, &session_key)
                    .open(&header[4..], rest)
                    .expect("packet authenticates"),
            );
            body
        };

        assert_eq!(body[16], 0, "header type: client");
        let padding_len = u16::from_be_bytes([body[25], body[26]]) as usize;
        let addr = &body[27 + padding_len..];
        let addr_len = socks_addr_len(addr);
        ClientPacket {
            session_id: be_u64(&body),
            packet_id: be_u64(&body[8..]),
            timestamp: be_u64(&body[17..]),
            padding_len,
            target: addr[..addr_len].to_vec(),
            data: addr[addr_len..].to_vec(),
        }
    }

    /// Build a server packet with header type 1.
    pub fn seal(
        &self,
        packet_id: u64,
        client_session_id: u64,
        timestamp: u64,
        padding_len: usize,
        source: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        self.seal_typed(
            1,
            packet_id,
            client_session_id,
            timestamp,
            padding_len,
            source,
            data,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_typed(
        &self,
        header_type: u8,
        packet_id: u64,
        client_session_id: u64,
        timestamp: u64,
        padding_len: usize,
        source: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut header = self.session_id.to_be_bytes().to_vec();
        header.extend(packet_id.to_be_bytes());
        let mut body = vec![header_type];
        body.extend(timestamp.to_be_bytes());
        body.extend(client_session_id.to_be_bytes());
        body.extend((padding_len as u16).to_be_bytes());
        body.resize(body.len() + padding_len, 0);
        body.extend(source);
        body.extend(data);

        if self.is_chacha() {
            let nonce = [0x5a; 24];
            header.extend(body);
            let mut packet = nonce.to_vec();
            packet.extend(Key::new("xchacha20-poly1305", self.psk()).seal(&nonce, &header));
            packet
        } else {
            let session_key =
                blake3_subkey(SESSION_SUBKEY, self.psk(), &self.session_id.to_be_bytes());
            let mut packet = aes_ecb_encrypt(self.psk(), &header).to_vec();
            packet.extend(Key::new(self.method, &session_key).seal(&header[4..], &body));
            packet
        }
    }
}
