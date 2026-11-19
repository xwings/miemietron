/// UDP relay for Shadowsocks — every packet is one self-contained datagram.
///
/// mihomo compat: the client packet conns of sing-shadowsocks2.
///
/// Stream ciphers and `none` (`shadowstream/method.go`, `cipher/method_none.go`):
///   [salt][keystream XOR (addr_header + data)]
/// Legacy AEAD (`shadowaead/method.go`):
///   [salt][encrypted(addr_header + data) + tag]
///   Each packet has a fresh random salt, so its nonce is all zeroes.
/// SS2022 (`shadowaead_2022/method.go`): see [`Session2022`].
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, RngCore};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::debug;

use super::aead::{
    decrypt_in_place_standalone, encode_address_into, encrypt_in_place_standalone, generate_salt,
    psk_hash, unix_now, AeadCipher, AesBlock, CipherCore, NONCE_LEN, TAG_LEN,
};
use super::stream::{Direction, StreamCipher};
use crate::common::addr::Address;
use crate::transport::tcp::ConnectOpts;

/// Nonce for legacy AEAD UDP packets — always zero (each packet has a fresh salt/key).
const ZERO_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

/// SS2022 `PacketNonceSize`: the XChaCha20-Poly1305 nonce leading a packet.
const XNONCE_LEN: usize = 24;
/// SS2022 `PacketMinimalHeaderSize`: a shorter packet is not looked into.
const MIN_PACKET_LEN_2022: usize = 30;
/// SS2022 `MaxPaddingLength`.
const MAX_PADDING_LEN: usize = 900;
const HEADER_TYPE_CLIENT: u8 = 0;
const HEADER_TYPE_SERVER: u8 = 1;

// Replay window geometry (`shadowaead_2022/slidingwindow.go`).
const SW_BLOCK_BIT_LOG: u64 = 6;
const SW_BLOCK_BITS: u64 = 1 << SW_BLOCK_BIT_LOG;
const SW_RING_BLOCKS: u64 = 1 << 7;
const SW_BLOCK_MASK: u64 = SW_RING_BLOCKS - 1;
const SW_BIT_MASK: u64 = SW_BLOCK_BITS - 1;
const SW_SIZE: u64 = (SW_RING_BLOCKS - 1) * SW_BLOCK_BITS;

/// Sliding window over packet ids: each id is accepted once, and not at all
/// once it has fallen `SW_SIZE` behind the highest one seen.
///
/// mihomo compat: a port of sing-shadowsocks2's `SlidingWindow`.
struct SlidingWindow {
    last: u64,
    ring: [u64; SW_RING_BLOCKS as usize],
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            last: 0,
            ring: [0; SW_RING_BLOCKS as usize],
        }
    }

    /// Whether `counter` can still be accepted.
    fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true; // ahead of window
        }
        if self.last - counter > SW_SIZE {
            return false; // behind window
        }
        let block = (counter >> SW_BLOCK_BIT_LOG) & SW_BLOCK_MASK;
        (self.ring[block as usize] >> (counter & SW_BIT_MASK)) & 1 == 0
    }

    /// Record `counter` as seen. `check` it first.
    fn add(&mut self, counter: u64) {
        let block = counter >> SW_BLOCK_BIT_LOG;
        if counter > self.last {
            let mut last_block = self.last >> SW_BLOCK_BIT_LOG;
            for _ in 0..(block - last_block).min(SW_RING_BLOCKS) {
                last_block = (last_block + 1) & SW_BLOCK_MASK;
                self.ring[last_block as usize] = 0;
            }
            self.last = counter;
        }
        self.ring[(block & SW_BLOCK_MASK) as usize] |= 1 << (counter & SW_BIT_MASK);
    }
}

/// The server sessions a client session has heard from: the current one and
/// the one before it (`udpSession`'s `remote*` and `lastRemote*` fields).
struct RemoteSessions {
    session_id: u64,
    cipher: Option<CipherCore>,
    window: SlidingWindow,
    last_session_id: u64,
    last_cipher: Option<CipherCore>,
    last_window: SlidingWindow,
    /// When the previous session was last heard from or replaced, Unix seconds.
    last_seen: u64,
}

/// The keys of a SS2022 UDP session.
#[allow(clippy::large_enum_variant)]
enum Keys2022 {
    /// `2022-blake3-aes-*-gcm`: a separate packet header under AES-ECB and a
    /// body under a per-session AEAD key.
    Aes {
        cipher: AeadCipher,
        /// The last configured PSK: session keys derive from it.
        psk: Vec<u8>,
        /// `udpBlockEncryptCipher`: the first configured PSK.
        header_enc: AesBlock,
        /// `udpBlockDecryptCipher`: the last configured PSK.
        header_dec: AesBlock,
        /// Per identity PSK, its block cipher and the hash of the PSK
        /// configured after it.
        identity: Vec<(AesBlock, [u8; 16])>,
        /// Body cipher of the packets this session sends.
        session: CipherCore,
    },
    /// `2022-blake3-chacha20-poly1305`: the whole packet under
    /// XChaCha20-Poly1305, keyed by the PSK itself (`udpCipher`).
    ChaCha(XChaCha20Poly1305),
}

/// Client side of a SIP022 UDP session.
///
/// mihomo compat: sing-shadowsocks2 `shadowaead_2022/method.go`
/// clientPacketConn and `protocol.go` udpSession.
///
/// AES methods, client -> server:
///   [AES-ECB(session_id(8) + packet_id(8))]
///   [identity header (16) per identity PSK]
///   [AEAD(type(1)=0 + timestamp(8) + padding_len(2) + padding + addr_header + data) + tag]
///   The AEAD nonce is bytes 4..16 of the packet header before encryption.
/// ChaCha method, client -> server:
///   [nonce(24)][AEAD(session_id(8) + packet_id(8) + type ... data) + tag]
/// Server -> client packets have type 1 and carry the client session id after
/// the timestamp; their packet header is encrypted with the last PSK.
pub(super) struct Session2022 {
    session_id: u64,
    next_packet_id: AtomicU64,
    keys: Keys2022,
    remote: parking_lot::Mutex<RemoteSessions>,
}

impl Session2022 {
    /// `identity_psks` and `psk` are the configured key list in order.
    pub(super) fn new(cipher: AeadCipher, identity_psks: &[Vec<u8>], psk: &[u8]) -> Self {
        Self::with_session_id(cipher, identity_psks, psk, rand::thread_rng().gen())
    }

    fn with_session_id(
        cipher: AeadCipher,
        identity_psks: &[Vec<u8>],
        psk: &[u8],
        session_id: u64,
    ) -> Self {
        let keys = if cipher == AeadCipher::Blake3ChaCha20Poly1305 {
            Keys2022::ChaCha(XChaCha20Poly1305::new(psk.into()))
        } else {
            let identity = identity_psks
                .iter()
                .enumerate()
                .map(|(i, identity_psk)| {
                    let next_psk = identity_psks.get(i + 1).map_or(psk, Vec::as_slice);
                    (AesBlock::new(identity_psk), psk_hash(next_psk))
                })
                .collect();
            Keys2022::Aes {
                cipher,
                psk: psk.to_vec(),
                header_enc: AesBlock::new(identity_psks.first().map_or(psk, Vec::as_slice)),
                header_dec: AesBlock::new(psk),
                identity,
                session: CipherCore::new(
                    cipher,
                    cipher.derive_subkey(psk, &session_id.to_be_bytes()),
                ),
            }
        };
        Self {
            session_id,
            next_packet_id: AtomicU64::new(0),
            keys,
            remote: parking_lot::Mutex::new(RemoteSessions {
                session_id: 0,
                cipher: None,
                window: SlidingWindow::new(),
                last_session_id: 0,
                last_cipher: None,
                last_window: SlidingWindow::new(),
                last_seen: 0,
            }),
        }
    }

    /// Build the packet carrying `data` to `target`; `now` is Unix seconds.
    fn encode(&self, data: &[u8], target: &Address, now: u64) -> Result<Vec<u8>> {
        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        // mihomo compat: only DNS-sized packets to port 53 are padded.
        let padding_len = if target.port() == 53 && data.len() < MAX_PADDING_LEN {
            rand::thread_rng().gen_range(1..=MAX_PADDING_LEN - data.len())
        } else {
            0
        };

        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&self.session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet_id.to_be_bytes());

        let mut body = Vec::with_capacity(16 + 11 + padding_len + 32 + data.len() + TAG_LEN);
        if matches!(self.keys, Keys2022::ChaCha(_)) {
            body.extend_from_slice(&header);
        }
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&now.to_be_bytes());
        body.extend_from_slice(&(padding_len as u16).to_be_bytes());
        body.resize(body.len() + padding_len, 0);
        encode_address_into(target, &mut body);
        body.extend_from_slice(data);

        let mut packet = Vec::with_capacity(XNONCE_LEN + 48 + body.len() + TAG_LEN);
        match &self.keys {
            Keys2022::ChaCha(cipher) => {
                let mut nonce = XNonce::default();
                rand::thread_rng().fill_bytes(&mut nonce);
                cipher
                    .encrypt_in_place(&nonce, b"", &mut body)
                    .map_err(|e| anyhow!("xchacha20-poly1305 encrypt: {e}"))?;
                packet.extend_from_slice(&nonce);
            }
            Keys2022::Aes {
                header_enc,
                identity,
                session,
                ..
            } => {
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&header[4..]);
                session.encrypt_in_place(&nonce, &mut body)?;

                let mut encrypted_header = header;
                header_enc.encrypt(&mut encrypted_header);
                packet.extend_from_slice(&encrypted_header);
                for (identity_cipher, next_psk_hash) in identity {
                    let mut identity_header = *next_psk_hash;
                    for (byte, mask) in identity_header.iter_mut().zip(header) {
                        *byte ^= mask;
                    }
                    identity_cipher.encrypt(&mut identity_header);
                    packet.extend_from_slice(&identity_header);
                }
            }
        }
        packet.extend_from_slice(&body);
        Ok(packet)
    }

    /// Open a packet from the server; `now` is Unix seconds. Returns the
    /// address the data came from and the data.
    fn decode(&self, packet: &[u8], now: u64) -> Result<(Address, Vec<u8>)> {
        let mut remote = self.remote.lock();
        let unique = |remote: &RemoteSessions, session_id: u64, packet_id: u64| {
            if session_id == remote.session_id {
                remote.window.check(packet_id)
            } else if session_id == remote.last_session_id {
                remote.last_window.check(packet_id)
            } else {
                true
            }
        };

        // The decrypted packet, where in it the part after the session and
        // packet ids starts, and the body cipher of a server session not
        // heard from before.
        let (session_id, packet_id, body, ids_len, new_cipher) = match &self.keys {
            Keys2022::ChaCha(cipher) => {
                if packet.len() < XNONCE_LEN + MIN_PACKET_LEN_2022 {
                    bail!("packet too short");
                }
                let (nonce, sealed) = packet.split_at(XNONCE_LEN);
                let mut body = sealed.to_vec();
                cipher
                    .decrypt_in_place(XNonce::from_slice(nonce), b"", &mut body)
                    .map_err(|e| anyhow!("decrypt packet: {e}"))?;
                let mut ids = body.as_slice();
                let session_id = take_u64(&mut ids)?;
                let packet_id = take_u64(&mut ids)?;
                if !unique(&remote, session_id, packet_id) {
                    bail!("packet id not unique");
                }
                (session_id, packet_id, body, 16, None)
            }
            Keys2022::Aes {
                cipher,
                psk,
                header_dec,
                ..
            } => {
                if packet.len() < MIN_PACKET_LEN_2022 {
                    bail!("packet too short");
                }
                let mut header = [0u8; 16];
                header.copy_from_slice(&packet[..16]);
                header_dec.decrypt(&mut header);
                let mut ids = header.as_slice();
                let session_id = take_u64(&mut ids)?;
                let packet_id = take_u64(&mut ids)?;
                if !unique(&remote, session_id, packet_id) {
                    bail!("packet id not unique");
                }

                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&header[4..]);
                let mut body = packet[16..].to_vec();
                let known_cipher = if session_id == remote.session_id {
                    remote.cipher.as_ref()
                } else if session_id == remote.last_session_id {
                    remote.last_cipher.as_ref()
                } else {
                    None
                };
                let new_cipher = match known_cipher {
                    Some(known_cipher) => known_cipher
                        .decrypt_in_place(&nonce, &mut body)
                        .map(|()| None),
                    None => {
                        let subkey = cipher.derive_subkey(psk, &header[..8]);
                        let new_cipher = CipherCore::new(*cipher, subkey);
                        new_cipher
                            .decrypt_in_place(&nonce, &mut body)
                            .map(|()| Some(new_cipher))
                    }
                }
                .map_err(|e| anyhow!("decrypt packet: {e}"))?;
                (session_id, packet_id, body, 0, new_cipher)
            }
        };

        let mut rest = &body[ids_len..];
        let header_type = take(&mut rest, 1)?[0];
        if header_type != HEADER_TYPE_SERVER {
            bail!("bad header type: expected {HEADER_TYPE_SERVER}, got {header_type}");
        }
        let epoch = take_u64(&mut rest)?;
        let diff = (now as i64).wrapping_sub(epoch as i64).unsigned_abs();
        if diff > 30 {
            bail!("bad timestamp: received {epoch}, diff {diff}s");
        }

        if session_id == remote.session_id {
            remote.window.add(packet_id);
        } else if session_id == remote.last_session_id {
            remote.last_window.add(packet_id);
            remote.last_seen = now;
        } else {
            if remote.session_id != 0 {
                if now.saturating_sub(remote.last_seen) < 60 {
                    bail!("server session changed more than once during the last minute");
                }
                remote.last_session_id = remote.session_id;
                remote.last_window = std::mem::replace(&mut remote.window, SlidingWindow::new());
                remote.last_seen = now;
                remote.last_cipher = remote.cipher.take();
            }
            remote.session_id = session_id;
            remote.cipher = new_cipher;
            remote.window.add(packet_id);
        }

        if take_u64(&mut rest)? != self.session_id {
            bail!("bad client session id");
        }
        let padding_len = take(&mut rest, 2)?;
        let padding_len = u16::from_be_bytes([padding_len[0], padding_len[1]]);
        take(&mut rest, padding_len as usize)?;
        let (addr, addr_len) = parse_address(rest)?;

        let data_at = body.len() - rest.len() + addr_len;
        let mut data = body;
        data.drain(..data_at);
        Ok((addr, data))
    }
}

/// Take the next `n` bytes of a decrypted packet.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if rest.len() < n {
        bail!("packet too short");
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_u64(rest: &mut &[u8]) -> Result<u64> {
    let (head, tail) = rest
        .split_first_chunk()
        .ok_or_else(|| anyhow!("packet too short"))?;
    *rest = tail;
    Ok(u64::from_be_bytes(*head))
}

/// How a method turns datagrams into packets and back.
pub(super) enum PacketCodec {
    Stream { cipher: StreamCipher, key: Vec<u8> },
    Aead { cipher: AeadCipher, key: Vec<u8> },
    Aead2022(Box<Session2022>),
}

impl PacketCodec {
    /// Build the packet carrying `data` to `target`.
    fn encode(&self, data: &[u8], target: &Address) -> Result<Vec<u8>> {
        match self {
            PacketCodec::Stream { cipher, key } => {
                let mut packet = generate_salt(cipher.salt_len());
                let salt_len = packet.len();
                encode_address_into(target, &mut packet);
                packet.extend_from_slice(data);
                let (salt, body) = packet.split_at_mut(salt_len);
                cipher.keystream(key, salt, Direction::Encrypt)(body)?;
                Ok(packet)
            }
            PacketCodec::Aead { cipher, key } => {
                // Single allocation: [salt | addr_header + data (plaintext, encrypted in-place + tag)]
                // Capacity hint only — a domain addr header can be up to 259 bytes,
                // in which case the Vec grows once.
                let mut plaintext = Vec::with_capacity(data.len() + 32);
                encode_address_into(target, &mut plaintext);
                plaintext.extend_from_slice(data);

                // Generate a random salt and derive the per-packet subkey
                let mut packet = generate_salt(cipher.salt_len());
                let subkey = cipher.derive_subkey(key, &packet);

                // Encrypt in place (appends tag)
                encrypt_in_place_standalone(cipher, &subkey, &ZERO_NONCE, &mut plaintext)?;

                // Build wire packet: salt + ciphertext_with_tag
                packet.extend_from_slice(&plaintext);
                Ok(packet)
            }
            PacketCodec::Aead2022(session) => session.encode(data, target, unix_now()),
        }
    }

    /// Open a received packet. Returns the address the data came from, as
    /// encoded in the packet, and the data.
    fn decode(&self, packet: &[u8]) -> Result<(Address, Vec<u8>)> {
        let mut plaintext = match self {
            PacketCodec::Stream { cipher, key } => {
                let salt_len = cipher.salt_len();
                if packet.len() < salt_len {
                    bail!("SS UDP: packet too short ({} bytes)", packet.len());
                }
                let (salt, body) = packet.split_at(salt_len);
                let mut plaintext = body.to_vec();
                cipher.keystream(key, salt, Direction::Decrypt)(&mut plaintext)?;
                plaintext
            }
            PacketCodec::Aead { cipher, key } => {
                let salt_len = cipher.salt_len();
                if packet.len() < salt_len + TAG_LEN {
                    bail!(
                        "SS UDP: packet too short ({} bytes, need at least {})",
                        packet.len(),
                        salt_len + TAG_LEN
                    );
                }
                let (salt, ciphertext) = packet.split_at(salt_len);
                let mut plaintext = ciphertext.to_vec();

                // Derive per-packet subkey
                let subkey = cipher.derive_subkey(key, salt);

                // Decrypt in place (removes tag)
                decrypt_in_place_standalone(cipher, &subkey, &ZERO_NONCE, &mut plaintext)?;
                plaintext
            }
            PacketCodec::Aead2022(session) => return session.decode(packet, unix_now()),
        };

        // Parse the address header from the decrypted payload
        let (addr, header_len) = parse_address(&plaintext)?;
        plaintext.drain(..header_len);
        Ok((addr, plaintext))
    }
}

/// Shadowsocks UDP socket — wraps a `UdpSocket` and encrypts/decrypts each packet.
pub struct SsUdpSocket {
    inner: UdpSocket,
    codec: PacketCodec,
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
}

impl SsUdpSocket {
    /// Create a new `SsUdpSocket` that communicates with the given SS server.
    ///
    /// mihomo compat: `ss.dialer.ListenPacket` — the socket takes the proxy's
    /// dialer options as the TCP dial does: `routing-mark` when configured
    /// (GID 65534, set by OpenClash via procd, handles firewall bypass
    /// otherwise) and `interface-name`, else the default outbound interface.
    pub(super) async fn new(
        server_addr: SocketAddr,
        codec: PacketCodec,
        opts: &ConnectOpts,
    ) -> Result<Self> {
        let (domain, unspecified) = match server_addr {
            SocketAddr::V4(_) => (Domain::IPV4, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            SocketAddr::V6(_) => (Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        #[cfg(target_os = "linux")]
        {
            if let Some(mark) = opts.routing_mark {
                socket.set_mark(mark)?;
            }
            let iface = opts
                .interface
                .clone()
                .or_else(crate::transport::tcp::default_outbound_interface_public);
            if let Some(iface) = iface {
                socket.bind_device(Some(iface.as_bytes()))?;
            }
        }

        socket.bind(&SocketAddr::new(unspecified, 0).into())?;
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket.into())?;
        socket.connect(server_addr).await?;

        Ok(Self {
            inner: socket,
            codec,
            recv_buf: tokio::sync::Mutex::new(vec![0u8; 65535]),
        })
    }

    /// Send `data` to `target` through the SS server.
    pub async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize> {
        let packet = self.codec.encode(data, target)?;
        let n = self.inner.send(&packet).await?;
        debug!(
            "SS UDP sent {} bytes to {} (wire: {} bytes)",
            data.len(),
            target,
            n
        );
        Ok(data.len())
    }

    /// Receive a UDP datagram from the SS server, decrypt it, and return
    /// the decrypted payload (without the address header) and the source address.
    ///
    /// Returns `(data, address)` where address is the remote sender's address
    /// as encoded in the SS packet header.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let mut recv_buf = self.recv_buf.lock().await;
        let n = self.inner.recv(&mut recv_buf).await?;
        let (addr, data) = self.codec.decode(&recv_buf[..n])?;

        let copy_len = std::cmp::min(data.len(), buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);

        debug!(
            "SS UDP recv {} bytes from {} (wire: {} bytes)",
            copy_len, addr, n
        );

        Ok((copy_len, addr))
    }
}

/// Implement `OutboundPacketConn` for `SsUdpSocket` — delegates to existing methods.
#[async_trait::async_trait]
impl crate::proxy::OutboundPacketConn for SsUdpSocket {
    async fn send_to(&self, data: &[u8], target: &Address) -> Result<usize> {
        SsUdpSocket::send_to(self, data, target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        SsUdpSocket::recv_from(self, buf).await
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Parse a Shadowsocks address header from `data`.
/// Returns `(Address, bytes_consumed)`.
///
/// Format: `[addr_type(1)][addr_data][port(2 BE)]`
fn parse_address(data: &[u8]) -> Result<(Address, usize)> {
    if data.is_empty() {
        return Err(anyhow!("SS UDP: empty address data"));
    }

    match data[0] {
        0x01 => {
            // IPv4: 1 + 4 + 2 = 7 bytes
            if data.len() < 7 {
                return Err(anyhow!("SS UDP: truncated IPv4 address"));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((
                Address::Ip(SocketAddr::new(std::net::IpAddr::V4(ip), port)),
                7,
            ))
        }
        0x03 => {
            // Domain: 1 + 1(len) + domain + 2(port)
            if data.len() < 2 {
                return Err(anyhow!("SS UDP: truncated domain address"));
            }
            let domain_len = data[1] as usize;
            let total = 1 + 1 + domain_len + 2;
            if data.len() < total {
                return Err(anyhow!("SS UDP: truncated domain address data"));
            }
            let domain = String::from_utf8(data[2..2 + domain_len].to_vec())
                .map_err(|_| anyhow!("SS UDP: invalid domain encoding"))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok((Address::Domain(domain, port), total))
        }
        0x04 => {
            // IPv6: 1 + 16 + 2 = 19 bytes
            if data.len() < 19 {
                return Err(anyhow!("SS UDP: truncated IPv6 address"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            // mihomo compat: sing reports an IPv4-mapped source as IPv4
            // (`Socksaddr.Unwrap`).
            let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((Address::Ip(SocketAddr::new(ip, port)), 19))
        }
        other => Err(anyhow!("SS UDP: unknown address type 0x{other:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::aead::encode_address;
    use super::super::test_support::{legacy_subkey, Key, UdpServer2022};
    use super::*;
    use crate::common::addr::Address;

    #[test]
    fn test_parse_address_ipv4() {
        // addr_type=1, ip=1.2.3.4, port=443
        let data = [0x01, 1, 2, 3, 4, 0x01, 0xBB];
        let (addr, len) = parse_address(&data).unwrap();
        assert_eq!(len, 7);
        match addr {
            Address::Ip(sa) => {
                assert_eq!(
                    sa.ip(),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))
                );
                assert_eq!(sa.port(), 443);
            }
            _ => panic!("expected IP address"),
        }
    }

    #[test]
    fn test_parse_address_domain() {
        // addr_type=3, len=11, "example.com", port=8080
        let mut data = vec![0x03, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&8080u16.to_be_bytes());
        let (addr, len) = parse_address(&data).unwrap();
        assert_eq!(len, 15);
        match addr {
            Address::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 8080);
            }
            _ => panic!("expected domain address"),
        }
    }

    #[test]
    fn test_parse_address_ipv6() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        data.extend_from_slice(&80u16.to_be_bytes());
        let (addr, len) = parse_address(&data).unwrap();
        assert_eq!(len, 19);
        match addr {
            Address::Ip(sa) => {
                assert_eq!(sa.port(), 80);
            }
            _ => panic!("expected IP address"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = AeadCipher::Aes256Gcm;
        let key = vec![0x42u8; 32];
        let nonce = [0u8; 12];
        let original = b"hello world".to_vec();

        let mut data = original.clone();
        encrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_ne!(data, original); // encrypted != plaintext
        assert_eq!(data.len(), original.len() + TAG_LEN); // tag appended

        decrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_eq!(data, original); // back to original
    }

    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let cipher = AeadCipher::ChaCha20Poly1305;
        let key = vec![0xAB; 32];
        let nonce = [0u8; 12];
        let original = b"test data for chacha".to_vec();

        let mut data = original.clone();
        encrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        decrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_encrypt_decrypt_aes128() {
        let cipher = AeadCipher::Aes128Gcm;
        let key = vec![0xCD; 16];
        let nonce = [0u8; 12];
        let original = b"aes128 test".to_vec();

        let mut data = original.clone();
        encrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        decrypt_in_place_standalone(&cipher, &key, &nonce, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_full_packet_roundtrip() {
        // Simulate what send_to / recv_from does:
        // Build packet: salt + encrypt(addr_header + data)
        let cipher = AeadCipher::Aes256Gcm;
        let master_key = vec![0x55u8; 32];
        let target = Address::Domain("example.com".to_string(), 443);
        let payload = b"GET / HTTP/1.1\r\n";

        let salt = generate_salt(cipher.salt_len());
        let subkey = cipher.derive_subkey(&master_key, &salt);

        let addr_header = encode_address(&target);
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&addr_header);
        plaintext.extend_from_slice(payload);

        let original_plaintext = plaintext.clone();

        encrypt_in_place_standalone(&cipher, &subkey, &ZERO_NONCE, &mut plaintext).unwrap();

        // The codec opens the packet built by hand
        let codec = PacketCodec::Aead {
            cipher,
            key: master_key.clone(),
        };
        let (addr, data) = codec
            .decode(&[salt.as_slice(), &plaintext].concat())
            .unwrap();
        assert_eq!(addr, target);
        assert_eq!(data, payload);

        // Now decrypt
        let subkey2 = cipher.derive_subkey(&master_key, &salt);
        decrypt_in_place_standalone(&cipher, &subkey2, &ZERO_NONCE, &mut plaintext).unwrap();
        assert_eq!(plaintext, original_plaintext);

        // Parse the address back
        let (addr, hdr_len) = parse_address(&plaintext).unwrap();
        assert_eq!(addr, target);
        assert_eq!(&plaintext[hdr_len..], payload);
    }

    /// Unix seconds the SS2022 tests run at.
    const NOW: u64 = 1_700_000_000;

    /// Where the test server's replies claim to come from: 93.184.216.34:443.
    const SOURCE: [u8; 7] = [1, 93, 184, 216, 34, 1, 187];

    const SS2022_METHODS: [(AeadCipher, &str); 3] = [
        (AeadCipher::Blake3Aes128Gcm, "2022-blake3-aes-128-gcm"),
        (AeadCipher::Blake3Aes256Gcm, "2022-blake3-aes-256-gcm"),
        (
            AeadCipher::Blake3ChaCha20Poly1305,
            "2022-blake3-chacha20-poly1305",
        ),
    ];

    fn web() -> Address {
        Address::domain("example.com", 443)
    }

    fn source() -> Address {
        Address::ip("93.184.216.34:443".parse().unwrap())
    }

    /// A client session and the server it talks to, sharing one PSK.
    fn ss2022_pair(cipher: AeadCipher, method: &'static str) -> (Session2022, UdpServer2022) {
        let psk = vec![0x42u8; cipher.key_len()];
        (
            Session2022::new(cipher, &[], &psk),
            UdpServer2022::new(method, &[&psk], 77),
        )
    }

    fn error(result: Result<(Address, Vec<u8>)>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn sliding_window_takes_each_packet_id_once() {
        let mut window = SlidingWindow::new();
        for id in [0, 5, 3, 4, 1000] {
            assert!(window.check(id), "{id}");
            window.add(id);
            assert!(!window.check(id), "{id} again");
        }
        // Skipped ids stay open.
        assert!(window.check(2));
        assert!(window.check(999));

        // One whole turn of the ring ahead: 9192 lands on the bit 1000 had.
        window.add(1000 + SW_RING_BLOCKS * SW_BLOCK_BITS);
        assert!(!window.check(9192));
        assert!(window.check(9191));
        // What the window has moved past is refused, seen or not.
        assert!(window.check(9192 - SW_SIZE));
        assert!(!window.check(9192 - SW_SIZE - 1));
        assert!(!window.check(2));
    }

    /// mihomo compat: clientPacketConn.WritePacket, read as `newPacket` in
    /// sing-shadowsocks `shadowaead_2022/service.go` reads it.
    #[test]
    fn ss2022_packets_as_the_server_reads_them() {
        for (cipher, method) in SS2022_METHODS {
            let (client, server) = ss2022_pair(cipher, method);
            let dns = Address::ip("8.8.8.8:53".parse().unwrap());

            let packet = client.encode(b"hello", &web(), NOW).unwrap();
            let nonce_and_ids = if cipher == AeadCipher::Blake3ChaCha20Poly1305 {
                XNONCE_LEN + 16
            } else {
                16
            };
            assert_eq!(
                packet.len(),
                nonce_and_ids + 1 + 8 + 2 + encode_address(&web()).len() + 5 + TAG_LEN,
                "{method}"
            );
            let first = server.open(&packet);
            assert_eq!(first.packet_id, 0, "{method}");
            assert_eq!(first.timestamp, NOW, "{method}");
            assert_eq!(first.padding_len, 0, "{method}");
            assert_eq!(first.target, encode_address(&web()), "{method}");
            assert_eq!(first.data, b"hello", "{method}");

            // One session id for the whole connection, packet ids counting up.
            let second = server.open(&client.encode(b"again", &web(), NOW + 1).unwrap());
            assert_eq!(second.session_id, first.session_id, "{method}");
            assert_eq!(second.packet_id, 1, "{method}");
            assert_eq!(second.timestamp, NOW + 1, "{method}");

            // Only packets to port 53 shorter than 900 bytes are padded, by
            // `rand.Intn(900 - len) + 1` bytes.
            for _ in 0..64 {
                let query = server.open(&client.encode(&[7u8; 100], &dns, NOW).unwrap());
                assert!((1..=800).contains(&query.padding_len), "{method}");
                assert_eq!(query.target, encode_address(&dns), "{method}");
                assert_eq!(query.data, [7u8; 100], "{method}");
            }
            let large = server.open(&client.encode(&[7u8; 900], &dns, NOW).unwrap());
            assert_eq!(large.padding_len, 0, "{method}");
            assert_eq!(large.packet_id, 66, "{method}");
        }
    }

    /// mihomo compat: clientPacketConn.readPacket — the packet id window,
    /// the header type, the ±30 s timestamp and the echoed client session id.
    #[test]
    fn ss2022_replies_are_read_once_and_only_while_fresh() {
        for (cipher, method) in SS2022_METHODS {
            let (client, server) = ss2022_pair(cipher, method);
            let session_id = server
                .open(&client.encode(b"q", &web(), NOW).unwrap())
                .session_id;
            let reply = |packet_id, timestamp| {
                server.seal(packet_id, session_id, timestamp, 0, &SOURCE, b"answer")
            };

            // Padding is skipped; the source address and the data come out.
            let padded = server.seal(0, session_id, NOW, 37, &SOURCE, b"answer");
            let (from, data) = client.decode(&padded, NOW).unwrap();
            assert_eq!(from, source(), "{method}");
            assert_eq!(data, b"answer", "{method}");

            // A replayed packet is refused; ids may arrive in any order.
            assert_eq!(error(client.decode(&padded, NOW)), "packet id not unique");
            for packet_id in [3, 1, 2] {
                client.decode(&reply(packet_id, NOW), NOW).unwrap();
            }
            assert_eq!(
                error(client.decode(&reply(2, NOW), NOW)),
                "packet id not unique"
            );

            // 30 seconds either way is fresh, 31 is not.
            client.decode(&reply(10, NOW - 30), NOW).unwrap();
            client.decode(&reply(11, NOW + 30), NOW).unwrap();
            assert_eq!(
                error(client.decode(&reply(12, NOW - 31), NOW)),
                format!("bad timestamp: received {}, diff 31s", NOW - 31)
            );
            assert_eq!(
                error(client.decode(&reply(12, NOW + 31), NOW)),
                format!("bad timestamp: received {}, diff 31s", NOW + 31)
            );
            // A refused packet is not counted as seen.
            client.decode(&reply(12, NOW), NOW).unwrap();

            let request = server.seal_typed(0, 13, session_id, NOW, 0, &SOURCE, b"answer");
            assert_eq!(
                error(client.decode(&request, NOW)),
                "bad header type: expected 1, got 0"
            );
            let for_another = server.seal(14, session_id ^ 1, NOW, 0, &SOURCE, b"answer");
            assert_eq!(
                error(client.decode(&for_another, NOW)),
                "bad client session id"
            );

            let mut tampered = reply(15, NOW);
            *tampered.last_mut().unwrap() ^= 1;
            let tampered = error(client.decode(&tampered, NOW));
            assert!(tampered.starts_with("decrypt packet: "), "{tampered}");
            let min_len = if cipher == AeadCipher::Blake3ChaCha20Poly1305 {
                XNONCE_LEN + MIN_PACKET_LEN_2022
            } else {
                MIN_PACKET_LEN_2022
            };
            assert_eq!(
                error(client.decode(&reply(16, NOW)[..min_len - 1], NOW)),
                "packet too short"
            );
        }
    }

    /// Packets a mihomo client (Meta alpha-gbeb1f27) sent to 10.9.8.7 with
    /// `captured datagram` in them, for several PSK lists (PSK `n` is the
    /// bytes n, n+1, ...). Given their session id, packet id and timestamp, a
    /// session here must put the very same bytes on the wire.
    #[test]
    fn ss2022_packets_match_mihomo() {
        let captures: [(AeadCipher, &'static str, &[u8], &str); 5] = [
            (
                AeadCipher::Blake3Aes128Gcm,
                "2022-blake3-aes-128-gcm",
                &[0],
                "b8bd539711fad6055a70ebfe534b6cbe1c6873b5e963a49ce774294b89db68bf4bbd887d332d36c4af\
                 c6ae8a16ac5eba8eb3391258c996ca63432bb32b190c34b104a5",
            ),
            (
                AeadCipher::Blake3Aes128Gcm,
                "2022-blake3-aes-128-gcm",
                &[0, 16],
                "a4f9b44a97e1ac8d1b96f9be0b6ac8157d70b6ca777746a8484b406d86a93edce4528185743d97e7fa\
                 fb3d4d5ff28c7791a119daea5a7c828a7e8148a8adfab6673ec9734ad464acd3ee1837ca321b97465c\
                 1f",
            ),
            (
                AeadCipher::Blake3Aes128Gcm,
                "2022-blake3-aes-128-gcm",
                &[0, 16, 32],
                "0a9928b2c998acd41bab6597846467b2c786db2bea617129691f66e272b5d8f4c2d74e23902d2e2a31\
                 101d01182248cb3f4a3ce2c65e8c2752fd4fc518a257842695ac703f74ce5308b39aad2430836cb48e\
                 586e41f9110822b6007f45e0c0ffc8d055",
            ),
            (
                AeadCipher::Blake3Aes256Gcm,
                "2022-blake3-aes-256-gcm",
                &[0],
                "8bf5f28749fc7ef602ed8cba2e230f667bc30ce5c86140a54c338defa983740de7c90e39d707b297ea\
                 da2c3cee1a2932b95f5ad52151711a9f86ee49010e9097a0fbbe",
            ),
            (
                AeadCipher::Blake3Aes256Gcm,
                "2022-blake3-aes-256-gcm",
                &[0, 100],
                "a535e2d918ff38d1f62abc6b40b7b40947ad1220b90fe707a266267e3c7a271736d4ad3480d39a44b5\
                 4f75cbcadf3fa33741172f860e8f2503f438be4f064c730122f6e08033544d0f01fa814d0059483dcc\
                 36",
            ),
        ];
        for (cipher, method, first_bytes, captured) in captures {
            let psks: Vec<Vec<u8>> = first_bytes
                .iter()
                .map(|&first| (first..first + cipher.key_len() as u8).collect())
                .collect();
            let chain: Vec<&[u8]> = psks.iter().map(Vec::as_slice).collect();
            let captured = hex::decode(captured).unwrap();

            let seen = UdpServer2022::new(method, &chain, 0).open(&captured);
            assert_eq!(seen.data, b"captured datagram");
            assert_eq!(seen.padding_len, 0);
            let (target, _) = parse_address(&seen.target).unwrap();
            assert_eq!(target.host(), "10.9.8.7");

            let (psk, identity_psks) = psks.split_last().unwrap();
            let client = Session2022::with_session_id(cipher, identity_psks, psk, seen.session_id);
            client
                .next_packet_id
                .store(seen.packet_id, Ordering::Relaxed);
            let packet = client.encode(&seen.data, &target, seen.timestamp).unwrap();
            assert_eq!(
                hex::encode(packet),
                hex::encode(&captured),
                "{method} with {} PSKs",
                psks.len()
            );
        }
    }

    /// mihomo compat: readPacket's session bookkeeping — a server may start
    /// a new session, packets of its previous one are still taken, and a
    /// second change within a minute is refused.
    #[test]
    fn ss2022_server_session_may_change_once_a_minute() {
        for (cipher, method) in SS2022_METHODS {
            let psk = vec![0x42u8; cipher.key_len()];
            let client = Session2022::new(cipher, &[], &psk);
            let [first, second, third] =
                [100, 200, 300].map(|session_id| UdpServer2022::new(method, &[&psk], session_id));
            let session_id = first
                .open(&client.encode(b"q", &web(), NOW).unwrap())
                .session_id;
            let reply = |server: &UdpServer2022, packet_id, timestamp| {
                server.seal(packet_id, session_id, timestamp, 0, &SOURCE, b"answer")
            };

            client.decode(&reply(&first, 0, NOW), NOW).unwrap();
            // The server restarted: its new session is taken up at once.
            client.decode(&reply(&second, 0, NOW + 1), NOW + 1).unwrap();
            // Stragglers of the old session still arrive, once each.
            client.decode(&reply(&first, 1, NOW + 1), NOW + 1).unwrap();
            assert_eq!(
                error(client.decode(&reply(&first, 1, NOW + 1), NOW + 1)),
                "packet id not unique",
                "{method}"
            );

            let changed_again = "server session changed more than once during the last minute";
            assert_eq!(
                error(client.decode(&reply(&third, 0, NOW + 2), NOW + 2)),
                changed_again,
                "{method}"
            );
            // A minute after the old session was last heard from, it may.
            client
                .decode(&reply(&third, 0, NOW + 61), NOW + 61)
                .unwrap();
            client
                .decode(&reply(&second, 1, NOW + 61), NOW + 61)
                .unwrap();
            // Only one previous session is remembered.
            assert_eq!(
                error(client.decode(&reply(&first, 2, NOW + 62), NOW + 62)),
                changed_again,
                "{method}"
            );
        }
    }

    /// mihomo compat: with several PSKs the packet header is encrypted with
    /// the first, every identity PSK adds a header naming the next one, and
    /// the body — like everything the server sends back — is under the last.
    #[test]
    fn ss2022_identity_headers_name_every_next_psk() {
        for (cipher, method) in &SS2022_METHODS[..2] {
            for psk_count in [2usize, 3, 4] {
                let psks: Vec<Vec<u8>> = (0..psk_count)
                    .map(|i| vec![0x10 + i as u8; cipher.key_len()])
                    .collect();
                let (psk, identity_psks) = psks.split_last().unwrap();
                let client = Session2022::new(*cipher, identity_psks, psk);
                let chain: Vec<&[u8]> = psks.iter().map(Vec::as_slice).collect();
                let server = UdpServer2022::new(method, &chain, 77);

                let packet = client.encode(b"hello", &web(), NOW).unwrap();
                assert_eq!(
                    packet.len(),
                    16 + 16 * identity_psks.len()
                        + 1
                        + 8
                        + 2
                        + encode_address(&web()).len()
                        + 5
                        + TAG_LEN,
                    "{method} with {psk_count} PSKs"
                );
                // `open` checks each identity header against the next PSK.
                let opened = server.open(&packet);
                assert_eq!(opened.data, b"hello", "{method} with {psk_count} PSKs");

                let reply = server.seal(0, opened.session_id, NOW, 0, &SOURCE, b"answer");
                let (from, data) = client.decode(&reply, NOW).unwrap();
                assert_eq!(from, source());
                assert_eq!(data, b"answer", "{method} with {psk_count} PSKs");
            }
        }
    }

    /// Packets of the two AEAD methods added last, sealed by OpenSSL (and,
    /// for XChaCha20, HChaCha20 written out from draft-irtf-cfrg-xchacha):
    /// salt, then `1.2.3.4:53` and `dns?` under the all-zero nonce.
    #[test]
    fn legacy_aead_packets_known_answer() {
        for (cipher, key, packet) in [
            (
                AeadCipher::Aes192Gcm,
                "b3adc47839e047eb228870526dc8fc30b347287ffca3045d",
                "808182838485868788898a8b8c8d8e8f9091929394959697a0d6bc698aaf29242b8ca6399bdc6cf8f2\
                 c993ddeb64546907cade",
            ),
            (
                AeadCipher::XChaCha20Poly1305,
                "b3adc47839e047eb228870526dc8fc30b347287ffca3045dcea06b3fdf090acb",
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fffd1f32a9477ea45c6\
                 33c4f690233c896186d226e2b7934ff27b69",
            ),
        ] {
            let codec = PacketCodec::Aead {
                cipher,
                key: hex::decode(key).unwrap(),
            };
            let (from, data) = codec.decode(&hex::decode(packet).unwrap()).unwrap();
            assert_eq!(from, Address::ip("1.2.3.4:53".parse().unwrap()));
            assert_eq!(data, b"dns?");
        }
    }

    /// What every legacy AEAD method sends, opened as a server does: a
    /// per-packet HKDF-SHA1 subkey and the all-zero nonce.
    #[test]
    fn legacy_aead_packets_as_the_server_reads_them() {
        for (cipher, method, nonce_len) in [
            (AeadCipher::Aes128Gcm, "aes-128-gcm", 12),
            (AeadCipher::Aes192Gcm, "aes-192-gcm", 12),
            (AeadCipher::Aes256Gcm, "aes-256-gcm", 12),
            (AeadCipher::ChaCha20Poly1305, "chacha20-ietf-poly1305", 12),
            (AeadCipher::XChaCha20Poly1305, "xchacha20-ietf-poly1305", 24),
        ] {
            let key = vec![0x55u8; cipher.key_len()];
            let codec = PacketCodec::Aead {
                cipher,
                key: key.clone(),
            };
            let packet = codec.encode(b"query", &web()).unwrap();
            let (salt, sealed) = packet.split_at(cipher.salt_len());
            let plain = Key::new(method, &legacy_subkey(&key, salt))
                .open(&vec![0u8; nonce_len], sealed)
                .expect(method);
            assert_eq!(
                plain,
                [encode_address(&web()).as_slice(), b"query"].concat()
            );

            // And back: a reply under a salt of the server's.
            let salt = vec![0x99u8; cipher.salt_len()];
            let mut reply = salt.clone();
            reply.extend(Key::new(method, &legacy_subkey(&key, &salt)).seal(
                &vec![0u8; nonce_len],
                &[SOURCE.as_slice(), b"answer"].concat(),
            ));
            let (from, data) = codec.decode(&reply).unwrap();
            assert_eq!(from, source(), "{method}");
            assert_eq!(data, b"answer", "{method}");

            assert!(codec
                .decode(&reply[..cipher.salt_len() + TAG_LEN - 1])
                .is_err());
        }
    }

    /// Stream ciphers and `none`: the salt, then the address and the data
    /// under the keystream that salt starts (known answers for the
    /// keystreams are in `stream.rs`).
    #[test]
    fn stream_cipher_packets() {
        for name in [
            "none",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "rc4-md5",
            "chacha20-ietf",
            "xchacha20",
            "chacha20",
        ] {
            let cipher = StreamCipher::from_name(name).unwrap();
            let key = vec![0x33u8; cipher.key_len()];
            let codec = PacketCodec::Stream {
                cipher,
                key: key.clone(),
            };
            let plain = [encode_address(&web()).as_slice(), b"query"].concat();

            let packet = codec.encode(b"query", &web()).unwrap();
            assert_eq!(packet.len(), cipher.salt_len() + plain.len(), "{name}");
            let (salt, body) = packet.split_at(cipher.salt_len());
            let mut body = body.to_vec();
            cipher.keystream(&key, salt, Direction::Decrypt)(&mut body).unwrap();
            assert_eq!(body, plain, "{name}");

            let mut reply = vec![0x99u8; cipher.salt_len()];
            let mut body = [SOURCE.as_slice(), b"answer"].concat();
            cipher.keystream(&key, &reply, Direction::Encrypt)(&mut body).unwrap();
            reply.extend(body);
            let (from, data) = codec.decode(&reply).unwrap();
            assert_eq!(from, source(), "{name}");
            assert_eq!(data, b"answer", "{name}");

            assert!(codec.decode(&reply[..cipher.salt_len()]).is_err(), "{name}");
        }

        // `none` is the address and the data as they are.
        let codec = PacketCodec::Stream {
            cipher: StreamCipher::None,
            key: Vec::new(),
        };
        assert_eq!(
            codec.encode(b"query", &web()).unwrap(),
            [encode_address(&web()).as_slice(), b"query"].concat()
        );
    }

    /// The socket is of the server's address family.
    #[tokio::test]
    async fn socket_reaches_an_ipv6_server() {
        // Not every build host has an IPv6 loopback.
        let Ok(server) = UdpSocket::bind("[::1]:0").await else {
            return;
        };
        let codec = PacketCodec::Stream {
            cipher: StreamCipher::None,
            key: Vec::new(),
        };
        let socket = SsUdpSocket::new(server.local_addr().unwrap(), codec, &ConnectOpts::default())
            .await
            .unwrap();
        socket.send_to(b"query", &web()).await.unwrap();

        let mut packet = [0u8; 64];
        let (n, client) = server.recv_from(&mut packet).await.unwrap();
        assert_eq!(
            &packet[..n],
            [encode_address(&web()).as_slice(), b"query"].concat()
        );
        server
            .send_to(&[SOURCE.as_slice(), b"answer"].concat(), client)
            .await
            .unwrap();
        let mut answer = [0u8; 64];
        let (n, from) = socket.recv_from(&mut answer).await.unwrap();
        assert_eq!(&answer[..n], b"answer");
        assert_eq!(from, source());
    }
}
