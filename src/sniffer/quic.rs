//! QUIC client Initial inspection (RFC 9001 / RFC 9369).
//!
//! Initial protection keys are derived from the visible destination connection
//! ID. Only authenticated CRYPTO frames contribute to the ClientHello. The
//! caller owns the three-second collection deadline and replays every datagram.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use ring::{aead, hkdf};

use super::{read_client_hello, SniffAttempt};

// mihomo compat: component/sniffer/quic_sniffer.go maxCryptoStreamOffset.
const MAX_CRYPTO_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct Version {
    initial: u8,
    retry: u8,
    salt: &'static [u8],
    label_prefix: &'static str,
}

fn version(number: u32) -> Option<Version> {
    let (initial, retry, salt, label_prefix): (_, _, &[u8], _) = match number {
        0xff00001d => (
            0,
            3,
            &[
                0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
            ],
            "quic",
        ),
        1 => (
            0,
            3,
            &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            "quic",
        ),
        0x6b3343cf => (
            1,
            0,
            &[
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
            "quicv2",
        ),
        _ => return None,
    };
    Some(Version {
        initial,
        retry,
        salt,
        label_prefix,
    })
}

struct InitialKey {
    dcid: Vec<u8>,
    hp: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
    largest: i64,
}

impl InitialKey {
    fn new(dcid: &[u8], version: Version) -> Self {
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, version.salt).extract(dcid);
        let client = expand_label::<32>(&initial, "client in");
        let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
        Self {
            dcid: dcid.to_vec(),
            hp: expand_label(&client, &format!("{} hp", version.label_prefix)),
            key: expand_label(&client, &format!("{} key", version.label_prefix)),
            iv: expand_label(&client, &format!("{} iv", version.label_prefix)),
            largest: -1,
        }
    }

    fn decrypt(&mut self, packet: &[u8], number_offset: usize) -> Result<Vec<u8>, DecryptError> {
        let sample = packet
            .get(number_offset + 4..number_offset + 20)
            .ok_or(DecryptError::Malformed)?;
        let mut mask = aes::cipher::Block::<Aes128>::clone_from_slice(sample);
        Aes128::new((&self.hp).into()).encrypt_block(&mut mask);
        let first = packet[0] ^ (mask[0] & 0x0f);
        let number_len = usize::from(first & 3) + 1;
        let header_len = number_offset + number_len;
        let mut header = packet[..header_len].to_vec();
        header[0] = first;
        let mut truncated = 0i64;
        for i in 0..number_len {
            header[number_offset + i] ^= mask[1 + i];
            truncated = (truncated << 8) | i64::from(header[number_offset + i]);
        }
        let number = decode_packet_number(number_len, self.largest, truncated);
        let mut nonce = self.iv;
        for (dest, source) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *dest ^= source;
        }
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &self.key).expect("AES-128 key has 16 bytes"),
        );
        let mut payload = packet[header_len..].to_vec();
        let plaintext = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&header),
                &mut payload,
            )
            .map_err(|_| DecryptError::Authentication)?;
        let len = plaintext.len();
        payload.truncate(len);
        self.largest = self.largest.max(number);
        Ok(payload)
    }
}

enum DecryptError {
    Malformed,
    Authentication,
}

fn expand_label<const N: usize>(secret: &hkdf::Prk, label: &str) -> [u8; N] {
    struct Length(usize);
    impl hkdf::KeyType for Length {
        fn len(&self) -> usize {
            self.0
        }
    }
    let mut info = Vec::with_capacity(10 + label.len());
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let mut out = [0; N];
    secret
        .expand(&[&info], Length(N))
        .expect("fixed QUIC HKDF output length")
        .fill(&mut out)
        .expect("HKDF output has requested length");
    out
}

fn decode_packet_number(length: usize, largest: i64, truncated: i64) -> i64 {
    let expected = largest + 1;
    let window = 1i64 << (length * 8);
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate <= expected - window / 2 && candidate < (1i64 << 62) - window {
        candidate + window
    } else if candidate > expected + window / 2 && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// Bounded ClientHello reassembly for one client UDP flow.
#[derive(Default)]
pub struct QuicSniffer {
    version: Option<Version>,
    keys: Vec<InitialKey>,
    crypto: Vec<u8>,
    received: Vec<u64>,
    contiguous: usize,
    closed: bool,
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// `NeedMore(0)` requests another datagram, not more bytes in this one.
    /// Malformed input ends sniffing; damaged authenticated-packet candidates
    /// are ignored so a later valid Initial can still supply the domain.
    pub fn sniff(&mut self, mut datagram: &[u8]) -> SniffAttempt {
        if self.closed || datagram.is_empty() {
            return SniffAttempt::Fail;
        }
        let mut coalesced = false;
        while !datagram.is_empty() {
            match self.read_packet(datagram, coalesced) {
                Ok(length) if length > 0 && length <= datagram.len() => {
                    datagram = &datagram[length..];
                    coalesced = true;
                }
                _ => return self.finish(SniffAttempt::Fail),
            }
        }
        if self.contiguous >= 4 {
            let length = 4
                + ((usize::from(self.crypto[1]) << 16)
                    | (usize::from(self.crypto[2]) << 8)
                    | usize::from(self.crypto[3]));
            if length > MAX_CRYPTO_BYTES {
                return self.finish(SniffAttempt::Fail);
            }
        }
        match read_client_hello(&self.crypto[..self.contiguous]) {
            SniffAttempt::NeedMore(_) => SniffAttempt::NeedMore(0),
            result => self.finish(result),
        }
    }

    fn finish(&mut self, result: SniffAttempt) -> SniffAttempt {
        self.closed = true;
        self.keys.clear();
        self.crypto = Vec::new();
        self.received = Vec::new();
        result
    }

    fn read_packet(&mut self, packet: &[u8], coalesced: bool) -> Result<usize, ()> {
        let mut wire = packet;
        let first = take(&mut wire, 1)?[0];
        if first & 0x80 == 0 {
            return if coalesced { Ok(packet.len()) } else { Err(()) };
        }
        if first & 0x40 == 0 {
            return Err(());
        }
        let number = u32::from_be_bytes(take(&mut wire, 4)?.try_into().map_err(|_| ())?);
        let version = match self.version {
            Some(version) => version,
            None => {
                let version = version(number).ok_or(())?;
                self.version = Some(version);
                version
            }
        };
        let dcid_len = usize::from(take(&mut wire, 1)?[0]);
        if dcid_len == 0 {
            return Err(());
        }
        let dcid = take(&mut wire, dcid_len)?;
        let scid_len = usize::from(take(&mut wire, 1)?[0]);
        take(&mut wire, scid_len)?;
        let packet_type = (first >> 4) & 3;
        if packet_type == version.retry {
            return Ok(packet.len());
        }
        if packet_type == version.initial {
            let token_len = varint(&mut wire)?;
            take(&mut wire, usize::try_from(token_len).map_err(|_| ())?)?;
        }
        let body_len = usize::try_from(varint(&mut wire)?).map_err(|_| ())?;
        let number_offset = packet.len() - wire.len();
        take(&mut wire, body_len)?;
        let packet_end = number_offset + body_len;
        if packet_type != version.initial {
            return Ok(packet_end);
        }
        match self.decrypt(&packet[..packet_end], number_offset, dcid, version) {
            Ok(plaintext) => self.read_frames(&plaintext)?,
            // mihomo compat: a corrupt or old Initial must not end collection.
            Err(DecryptError::Authentication) => {}
            Err(DecryptError::Malformed) => return Err(()),
        }
        Ok(packet_end)
    }

    fn decrypt(
        &mut self,
        packet: &[u8],
        number_offset: usize,
        dcid: &[u8],
        version: Version,
    ) -> Result<Vec<u8>, DecryptError> {
        if self.keys.is_empty() {
            self.keys.push(InitialKey::new(dcid, version));
        }
        let mut known_dcid = false;
        let mut largest = -1;
        for key in &mut self.keys {
            known_dcid |= key.dcid == dcid;
            largest = largest.max(key.largest);
            match key.decrypt(packet, number_offset) {
                Ok(plaintext) => return Ok(plaintext),
                Err(DecryptError::Malformed) => return Err(DecryptError::Malformed),
                Err(DecryptError::Authentication) => {}
            }
        }
        if known_dcid {
            return Err(DecryptError::Authentication);
        }
        // Retry changes the key derivation DCID, but preserves packet numbers.
        // Retain the original epoch for reordered pre-Retry packets. A failed
        // candidate never evicts an authenticated epoch.
        let mut candidate = InitialKey::new(dcid, version);
        candidate.largest = largest;
        let plaintext = candidate.decrypt(packet, number_offset)?;
        if self.keys.len() == 1 {
            self.keys.push(candidate);
        } else {
            self.keys[1] = candidate;
        }
        Ok(plaintext)
    }

    fn read_frames(&mut self, mut wire: &[u8]) -> Result<(), ()> {
        while !wire.is_empty() {
            match take(&mut wire, 1)?[0] {
                0 | 1 => {} // PADDING / PING
                frame @ (2 | 3) => {
                    varint(&mut wire)?; // largest acknowledged
                    varint(&mut wire)?; // ACK delay
                    let count = varint(&mut wire)?;
                    varint(&mut wire)?; // first ACK range
                    for _ in 0..count {
                        varint(&mut wire)?;
                        varint(&mut wire)?;
                    }
                    if frame == 3 {
                        for _ in 0..3 {
                            varint(&mut wire)?;
                        }
                    }
                }
                6 => {
                    let offset = varint(&mut wire)?;
                    let len = usize::try_from(varint(&mut wire)?).map_err(|_| ())?;
                    let data = take(&mut wire, len)?;
                    self.add_crypto(offset, data)?;
                }
                0x1c => {
                    varint(&mut wire)?; // error code
                    varint(&mut wire)?; // frame type
                    let len = usize::try_from(varint(&mut wire)?).map_err(|_| ())?;
                    take(&mut wire, len)?;
                }
                _ => return Err(()),
            }
        }
        Ok(())
    }

    fn add_crypto(&mut self, offset: u64, data: &[u8]) -> Result<(), ()> {
        if data.is_empty() {
            return Ok(());
        }
        let offset = usize::try_from(offset).map_err(|_| ())?;
        let end = offset
            .checked_add(data.len())
            .filter(|n| *n <= MAX_CRYPTO_BYTES)
            .ok_or(())?;
        if self.crypto.len() < end {
            // Grow geometrically while keeping actual allocation capacity
            // within the same bound as retained CRYPTO bytes.
            if self.crypto.capacity() < end {
                self.crypto
                    .reserve_exact(end.next_power_of_two() - self.crypto.len());
            }
            self.crypto.resize(end, 0);
            let words = end.div_ceil(64);
            if self.received.capacity() < words {
                self.received
                    .reserve_exact(words.next_power_of_two() - self.received.len());
            }
            self.received.resize(words, 0);
        }
        self.crypto[offset..end].copy_from_slice(data);
        for at in offset..end {
            self.received[at / 64] |= 1u64 << (at % 64);
        }
        while self.contiguous < self.crypto.len()
            && self.received[self.contiguous / 64] & (1u64 << (self.contiguous % 64)) != 0
        {
            self.contiguous += 1;
        }
        Ok(())
    }
}

fn take<'a>(wire: &mut &'a [u8], count: usize) -> Result<&'a [u8], ()> {
    let data = wire.get(..count).ok_or(())?;
    *wire = &wire[count..];
    Ok(data)
}

fn varint(wire: &mut &[u8]) -> Result<u64, ()> {
    let first = *wire.first().ok_or(())?;
    let length = 1usize << (first >> 6);
    let data = take(wire, length)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &data[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn initial_fragments(host: &str) -> Vec<Vec<u8>> {
        let hello = super::super::tests::build_client_hello(host);
        let hello = &hello[5..];
        let split = hello.len() / 2;
        vec![
            packet(
                1,
                b"testdcid",
                b"testdcid",
                0,
                1,
                &crypto(0, &hello[..split]),
            ),
            packet(
                1,
                b"testdcid",
                b"testdcid",
                1,
                1,
                &crypto(split as u64, &hello[split..]),
            ),
        ]
    }

    pub(super) fn append_varint(wire: &mut Vec<u8>, value: u64) {
        let (len, prefix) = if value < 64 {
            (1, 0)
        } else if value < 16384 {
            (2, 0x40)
        } else if value < (1 << 30) {
            (4, 0x80)
        } else {
            (8, 0xc0)
        };
        let at = wire.len();
        wire.extend_from_slice(&value.to_be_bytes()[8 - len..]);
        wire[at] |= prefix;
    }

    pub(super) fn crypto(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![6];
        append_varint(&mut frame, offset);
        append_varint(&mut frame, data.len() as u64);
        frame.extend_from_slice(data);
        frame
    }

    pub(super) fn packet(
        number: u32,
        header_dcid: &[u8],
        key_dcid: &[u8],
        packet_number: i64,
        number_len: usize,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let version = version(number).unwrap();
        let key = InitialKey::new(key_dcid, version);
        let mut payload = plaintext.to_vec();
        payload.resize(payload.len().max(4 - number_len), 0);
        let mut header = vec![0xc0 | (version.initial << 4) | (number_len - 1) as u8];
        header.extend_from_slice(&number.to_be_bytes());
        header.push(header_dcid.len() as u8);
        header.extend_from_slice(header_dcid);
        header.extend_from_slice(&[0, 0]); // source CID and token lengths
        append_varint(&mut header, (number_len + payload.len() + 16) as u64);
        let number_offset = header.len();
        header.extend_from_slice(&packet_number.to_be_bytes()[8 - number_len..]);
        let mut nonce = key.iv;
        for (dest, source) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
            *dest ^= source;
        }
        let aead =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key.key).unwrap());
        aead.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&header),
            &mut payload,
        )
        .unwrap();
        let mut wire = header;
        wire.extend_from_slice(&payload);
        let mut mask = aes::cipher::Block::<Aes128>::clone_from_slice(
            &wire[number_offset + 4..number_offset + 20],
        );
        Aes128::new((&key.hp).into()).encrypt_block(&mut mask);
        wire[0] ^= mask[0] & 0xf;
        for i in 0..number_len {
            wire[number_offset + i] ^= mask[i + 1];
        }
        wire
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn fixture(text: &str) -> Vec<u8> {
        hex::decode(text.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn rfc_client_initials_decrypt_to_example_com() {
        // Independent wire vectors: RFC 9001 A.2 and RFC 9369 A.2.
        for vector in [
            include_str!("testdata/rfc9001-client-initial.hex"),
            include_str!("testdata/rfc9369-client-initial.hex"),
        ] {
            let wire = fixture(vector);
            assert!(
                matches!(QuicSniffer::new().sniff(&wire), SniffAttempt::Found(host) if host == "example.com")
            );
            for n in 0..wire.len() {
                // Every truncated wire prefix must fail cleanly, without panic.
                assert!(matches!(
                    QuicSniffer::new().sniff(&wire[..n]),
                    SniffAttempt::Fail
                ));
            }
        }
    }

    #[test]
    fn fragments_reassemble_across_datagrams_in_either_order_and_when_coalesced() {
        let fragments = initial_fragments("fragmented.example.com");
        for sequence in [vec![0, 1], vec![1, 0], vec![1, 1, 0]] {
            let mut sniffer = QuicSniffer::new();
            for i in &sequence[..sequence.len() - 1] {
                assert!(matches!(
                    sniffer.sniff(&fragments[*i]),
                    SniffAttempt::NeedMore(_)
                ));
            }
            assert!(
                matches!(sniffer.sniff(&fragments[*sequence.last().unwrap()]), SniffAttempt::Found(host) if host == "fragmented.example.com")
            );
        }
        let mut coalesced = fragments.concat();
        // Coalesced short-header packets have no Length and consume the tail.
        coalesced.extend_from_slice(&[0x40, 1, 2, 3]);
        assert!(
            matches!(QuicSniffer::new().sniff(&coalesced), SniffAttempt::Found(host) if host == "fragmented.example.com")
        );
    }

    #[test]
    fn all_supported_versions_and_corrupt_initial_recovery() {
        let hello = super::super::tests::build_client_hello("versions.example.com");
        for number in [0xff00001d, 1, 0x6b3343cf] {
            let valid = packet(number, b"dcid", b"dcid", 1, 2, &crypto(0, &hello[5..]));
            let mut corrupted = valid.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            let mut sniffer = QuicSniffer::new();
            assert!(matches!(
                sniffer.sniff(&corrupted),
                SniffAttempt::NeedMore(_)
            ));
            assert!(
                matches!(sniffer.sniff(&valid), SniffAttempt::Found(host) if host == "versions.example.com")
            );
        }
    }

    #[test]
    fn packet_number_reconstruction_and_retry_keys_survive_header_dcid_changes() {
        for (length, largest, truncated, expected) in [
            (1, -1, 0, 0),
            (1, 127, 0, 256),
            (1, 382, 0, 256),
            (1, 383, 0, 512),
            (2, 0xa82f30ea, 0x9b32, 0xa82f9b32),
        ] {
            assert_eq!(decode_packet_number(length, largest, truncated), expected);
        }
        let mut sniffer = QuicSniffer::new();
        let mut original = InitialKey::new(b"original", version(1).unwrap());
        original.largest = 200;
        sniffer.keys.push(original);
        let before_retry = packet(1, b"original", b"original", 201, 1, &[1]);
        assert!(matches!(
            sniffer.sniff(&before_retry),
            SniffAttempt::NeedMore(_)
        ));
        let after_retry = packet(1, b"retry", b"retry", 256, 1, &[1]);
        assert!(matches!(
            sniffer.sniff(&after_retry),
            SniffAttempt::NeedMore(_)
        ));
        assert_eq!(sniffer.keys.len(), 2);
        assert_eq!(sniffer.keys[1].largest, 256);
        let delayed = packet(1, b"original", b"original", 0, 1, &[1]);
        assert!(matches!(sniffer.sniff(&delayed), SniffAttempt::NeedMore(_)));
        let hello = super::super::tests::build_client_hello("retry.example.com");
        let changed_header = packet(1, b"original", b"retry", 257, 1, &crypto(0, &hello[5..]));
        assert!(
            matches!(sniffer.sniff(&changed_header), SniffAttempt::Found(host) if host == "retry.example.com")
        );
    }

    #[test]
    fn crypto_coverage_is_exact_and_bounded() {
        let packet = super::super::tests::build_client_hello("gaps.example.com");
        let hello = &packet[5..];
        let mut sniffer = QuicSniffer::new();
        // A one-byte gap must not be treated as initialized ClientHello bytes.
        sniffer.add_crypto(0, &hello[..1]).unwrap();
        sniffer.add_crypto(2, &hello[2..]).unwrap();
        assert_eq!(sniffer.contiguous, 1);
        sniffer.add_crypto(1, &hello[1..2]).unwrap();
        assert_eq!(sniffer.contiguous, hello.len());
        assert!(
            matches!(read_client_hello(&sniffer.crypto), SniffAttempt::Found(host) if host == "gaps.example.com")
        );
        // Exact 64 KiB coverage is allowed, including sparse final bytes.
        sniffer
            .add_crypto((MAX_CRYPTO_BYTES - 1) as u64, &[0])
            .unwrap();
        assert!(sniffer.crypto.len() <= MAX_CRYPTO_BYTES);
        assert!(sniffer.received.len() * 8 <= MAX_CRYPTO_BYTES / 8);
        assert!(sniffer.add_crypto(MAX_CRYPTO_BYTES as u64, &[1]).is_err());
        assert!(sniffer.add_crypto(u64::MAX, &[1]).is_err());
    }

    #[test]
    fn malformed_frames_and_oversized_crypto_are_rejected() {
        let mut frames = vec![0x1c, 0, 0];
        append_varint(&mut frames, (1u64 << 62) - 1);
        let mut sniffer = QuicSniffer::new();
        assert!(sniffer.read_frames(&frames).is_err());
        assert!(sniffer.read_frames(&[6, 0, 5, 1]).is_err());
        assert!(sniffer.read_frames(&[0x10]).is_err());
        let over = packet(
            1,
            b"dcid",
            b"dcid",
            1,
            1,
            &crypto(MAX_CRYPTO_BYTES as u64, &[1]),
        );
        assert!(matches!(
            QuicSniffer::new().sniff(&over),
            SniffAttempt::Fail
        ));
        let hello_header = [1, 1, 0, 0]; // declared body exceeds 64 KiB
        let huge = packet(1, b"dcid", b"dcid", 1, 1, &crypto(0, &hello_header));
        assert!(matches!(
            QuicSniffer::new().sniff(&huge),
            SniffAttempt::Fail
        ));
    }

    #[test]
    fn large_client_hello_reassembles_and_sni_does_not_wait_for_trailing_padding() {
        for before_sni in [true, false] {
            let record = super::super::tests::build_client_hello("large.example.com");
            let mut hello = record[5..].to_vec();
            let padding_len = 20000;
            let extensions = u16::from_be_bytes([hello[45], hello[46]]) + 4 + padding_len;
            hello[45..47].copy_from_slice(&extensions.to_be_bytes());
            let mut padding = vec![0, 0x15];
            padding.extend_from_slice(&padding_len.to_be_bytes());
            padding.resize(4 + usize::from(padding_len), 0);
            if before_sni {
                hello.splice(47..47, padding);
            } else {
                hello.extend_from_slice(&padding);
            }
            let length = (hello.len() - 4) as u32;
            hello[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
            let mut sniffer = QuicSniffer::new();
            let mut found = false;
            for (i, fragment) in hello.chunks(1000).enumerate() {
                let wire = packet(
                    1,
                    b"large",
                    b"large",
                    i as i64,
                    2,
                    &crypto((i * 1000) as u64, fragment),
                );
                match sniffer.sniff(&wire) {
                    SniffAttempt::Found(host) => {
                        assert_eq!(host, "large.example.com");
                        assert_eq!(i == 0, !before_sni);
                        found = true;
                        break;
                    }
                    SniffAttempt::NeedMore(_) => {}
                    SniffAttempt::Fail => panic!("valid ClientHello rejected"),
                }
            }
            assert!(found);
        }
    }

    #[test]
    fn coalesced_handshake_and_zero_rtt_packets_are_skipped_at_their_boundaries() {
        let parts = initial_fragments("coalesced.example.com");
        // v1 long-header 0-RTT / Handshake: version, DCID, SCID, Length, body.
        let non_initial = |kind: u8| {
            let mut wire = vec![0xc0 | kind << 4];
            wire.extend_from_slice(&1u32.to_be_bytes());
            wire.extend_from_slice(&[1, 9, 0, 3, 7, 8, 9]);
            wire
        };
        let wire = [
            parts[0].clone(),
            non_initial(1),
            non_initial(2),
            parts[1].clone(),
        ]
        .concat();
        assert!(
            matches!(QuicSniffer::new().sniff(&wire), SniffAttempt::Found(host) if host == "coalesced.example.com")
        );
    }
}
