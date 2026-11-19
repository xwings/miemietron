//! Server certificate checks for a REALITY handshake.
//!
//! A REALITY server proves it holds the configured private key by presenting
//! a throwaway Ed25519 certificate whose signature field is
//! HMAC-SHA512(auth key, public key). Anything else on the other end is the
//! camouflage site (or a middlebox), whose certificate is verified the
//! ordinary way so the connection can carry on looking like a browser's.

use anyhow::{anyhow, bail, Context as _, Result};
use ring::hmac;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{RootCertStore, SignatureScheme};
use std::io::Read;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Whose certificate the server presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Peer {
    /// The REALITY server: its certificate carries the auth-key HMAC.
    Reality,
    /// Something with a valid certificate for the camouflage name.
    Camouflage,
}

/// DER contents of the Ed25519 AlgorithmIdentifier: OID 1.3.101.112, no
/// parameters (RFC 8410).
const ED25519_ALGORITHM: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// The fields of an X.509 certificate the handshake looks at.
struct Certificate<'a> {
    /// Contents of the SubjectPublicKeyInfo's AlgorithmIdentifier.
    key_algorithm: &'a [u8],
    public_key: &'a [u8],
    signature: &'a [u8],
}

/// Split one DER element off the front of `input`: tag, contents, rest.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let width = (first & 0x7f) as usize;
        if width == 0 || width > 4 || rest.len() < width {
            return None;
        }
        let len = rest[..width]
            .iter()
            .fold(0usize, |len, &byte| (len << 8) | byte as usize);
        (len, &rest[width..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The contents of the next element, which must carry `tag`.
fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, contents, rest) = element(input)?;
    (found == tag).then_some((contents, rest))
}

/// A BIT STRING's bytes, which must have no unused bits.
fn bit_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (contents, rest) = expect(input, 0x03)?;
    let (&unused_bits, bytes) = contents.split_first()?;
    (unused_bits == 0).then_some((bytes, rest))
}

const SEQUENCE: u8 = 0x30;

fn parse(der: &[u8]) -> Option<Certificate<'_>> {
    let (certificate, _) = expect(der, SEQUENCE)?;
    let (tbs, rest) = expect(certificate, SEQUENCE)?;
    let (_signature_algorithm, rest) = expect(rest, SEQUENCE)?;
    let (signature, _) = bit_string(rest)?;

    // TBSCertificate: [0] version (optional), serialNumber, signature,
    // issuer, validity, subject, subjectPublicKeyInfo, ...
    let mut fields = tbs;
    if fields.first() == Some(&0xa0) {
        fields = element(fields)?.2;
    }
    for _ in 0..5 {
        fields = element(fields)?.2;
    }
    let (key_info, _) = expect(fields, SEQUENCE)?;
    let (key_algorithm, rest) = expect(key_info, SEQUENCE)?;
    let (public_key, _) = bit_string(rest)?;

    Some(Certificate {
        key_algorithm,
        public_key,
        signature,
    })
}

static WEB_PKI: LazyLock<Arc<WebPkiServerVerifier>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .expect("the bundled root store is not empty")
});

/// Decide whose certificate chain this is (leaf first).
///
/// mihomo compat: `realityVerifier.VerifyConnection` — a REALITY certificate
/// authenticates on its own; any other must verify for `server_name`.
pub(super) fn verify_chain(
    certificates: &[Vec<u8>],
    auth_key: &[u8; 32],
    server_name: &str,
    now: SystemTime,
) -> Result<Peer> {
    let leaf = certificates
        .first()
        .context("tls: received empty certificates message")?;
    if let Some(certificate) = parse(leaf) {
        if certificate.key_algorithm == ED25519_ALGORITHM && certificate.public_key.len() == 32 {
            let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
            if hmac::verify(&key, certificate.public_key, certificate.signature).is_ok() {
                return Ok(Peer::Reality);
            }
        }
    }

    let name = ServerName::try_from(server_name)
        .map_err(|error| anyhow!("x509: invalid server name {server_name:?}: {error}"))?;
    let intermediates: Vec<CertificateDer<'_>> = certificates[1..]
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let now = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).unwrap_or_default());
    WEB_PKI
        .verify_server_cert(
            &CertificateDer::from(leaf.as_slice()),
            &intermediates,
            &name,
            &[],
            now,
        )
        .map_err(|error| anyhow!("x509: {error}"))?;
    Ok(Peer::Camouflage)
}

/// Verify a TLS 1.3 CertificateVerify signature made by `leaf`'s key.
pub(super) fn verify_signature(
    leaf: &[u8],
    scheme: u16,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let certificate = parse(leaf).context("tls: failed to parse certificate from server")?;
    let scheme = SignatureScheme::from(scheme);
    // RFC 8446, Section 4.4.3: PKCS#1 v1.5 and SHA-1 never sign a TLS 1.3
    // handshake. Everything else the provider can verify is accepted, like
    // Go, whether or not the hello's signature_algorithms listed it — REALITY
    // signs with Ed25519, which no browser preset advertises.
    if matches!(
        scheme,
        SignatureScheme::RSA_PKCS1_SHA1
            | SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
            | SignatureScheme::ECDSA_SHA1_Legacy
    ) {
        bail!("certificate used with invalid signature algorithm");
    }
    let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
    // The first algorithm of a scheme is the one TLS 1.3 means by it: the
    // curve the scheme names, RSA-PSS with an rsaEncryption key.
    let algorithm = algorithms
        .mapping
        .iter()
        .find(|(candidate, _)| *candidate == scheme)
        .and_then(|(_, algorithms)| algorithms.first())
        .context("certificate used with invalid signature algorithm")?;
    if algorithm.public_key_alg_id().as_ref() != certificate.key_algorithm {
        bail!("certificate used with invalid signature algorithm");
    }
    algorithm
        .verify_signature(certificate.public_key, message, signature)
        .map_err(|_| anyhow!("signature verification failed"))
}

/// Certificates above this size are not worth decompressing (Go caps
/// handshake messages at 64 KiB as well).
const MAX_DECOMPRESSED_LEN: usize = 65536;

/// Turn a CompressedCertificate body (RFC 8879) into a Certificate body.
///
/// mihomo compat: uTLS `decompressCert`.
pub(super) fn decompress(body: &[u8]) -> Result<Vec<u8>> {
    let malformed = || anyhow!("tls: failed to decompress certificate message: malformed message");
    if body.len() < 8 {
        return Err(malformed());
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let uncompressed_len = u32::from_be_bytes([0, body[2], body[3], body[4]]) as usize;
    let compressed_len = u32::from_be_bytes([0, body[5], body[6], body[7]]) as usize;
    let compressed = &body[8..];
    if compressed.len() != compressed_len || uncompressed_len > MAX_DECOMPRESSED_LEN {
        return Err(malformed());
    }

    let mut decompressed = Vec::with_capacity(uncompressed_len);
    // One byte past the announced length, to notice a message that is longer.
    let limit = uncompressed_len as u64 + 1;
    let read = match algorithm {
        1 => flate2::read::ZlibDecoder::new(compressed)
            .take(limit)
            .read_to_end(&mut decompressed),
        2 => brotli_decompressor::Decompressor::new(compressed, 4096)
            .take(limit)
            .read_to_end(&mut decompressed),
        3 => ruzstd::decoding::StreamingDecoder::new(compressed)
            .map_err(|error| {
                anyhow!("tls: failed to decompress certificate message: failed to open zstd reader: {error}")
            })?
            .take(limit)
            .read_to_end(&mut decompressed),
        other => bail!(
            "tls: failed to decompress certificate message: unsupported algorithm ({other})"
        ),
    };
    read.map_err(|error| anyhow!("tls: failed to decompress certificate message: {error}"))?;
    if decompressed.len() != uncompressed_len {
        bail!(
            "tls: failed to decompress certificate message: decompressed len ({}) does not match specified len ({uncompressed_len})",
            decompressed.len()
        );
    }
    Ok(decompressed)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use ring::signature::KeyPair as _;
    use std::io::Write as _;

    /// A minimal DER element.
    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match contents.len() {
            len @ 0..=0x7f => out.push(len as u8),
            len @ 0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
            len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(contents);
        out
    }

    /// A structurally complete X.509 certificate around an Ed25519 key, with
    /// `signature` in its signature field — what a REALITY server presents.
    pub(crate) fn ed25519_certificate(public_key: &[u8], signature: &[u8]) -> Vec<u8> {
        let algorithm = der(SEQUENCE, ED25519_ALGORITHM);
        let name = der(SEQUENCE, &[]);
        let validity = der(
            SEQUENCE,
            &[der(0x17, b"240101000000Z"), der(0x17, b"340101000000Z")].concat(),
        );
        let key_info = der(
            SEQUENCE,
            &[
                algorithm.clone(),
                der(0x03, &[&[0u8][..], public_key].concat()),
            ]
            .concat(),
        );
        let tbs = der(
            SEQUENCE,
            &[
                der(0xa0, &der(0x02, &[2])),
                der(0x02, &[1]),
                algorithm.clone(),
                name.clone(),
                validity,
                name,
                key_info,
            ]
            .concat(),
        );
        der(
            SEQUENCE,
            &[tbs, algorithm, der(0x03, &[&[0u8][..], signature].concat())].concat(),
        )
    }

    /// A REALITY certificate for `auth_key`, and the key pair behind it.
    pub(crate) fn reality_certificate(
        auth_key: &[u8; 32],
    ) -> (Vec<u8>, ring::signature::Ed25519KeyPair) {
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, auth_key), &public_key);
        (ed25519_certificate(&public_key, tag.as_ref()), key_pair)
    }

    #[test]
    fn a_reality_certificate_authenticates_without_a_trust_chain() {
        let auth_key = [0x42; 32];
        let (certificate, _) = reality_certificate(&auth_key);
        let now = SystemTime::now();
        assert_eq!(
            verify_chain(&[certificate.clone()], &auth_key, "example.com", now).unwrap(),
            Peer::Reality
        );
        // Signed with any other key it is just an untrusted certificate.
        assert!(verify_chain(&[certificate], &[0x24; 32], "example.com", now).is_err());
        assert!(verify_chain(&[vec![0x30, 0x00]], &auth_key, "example.com", now).is_err());
        assert!(verify_chain(&[], &auth_key, "example.com", now).is_err());
    }

    #[test]
    fn certificate_verify_checks_the_leaf_key_and_the_scheme() {
        let (certificate, key_pair) = reality_certificate(&[0x42; 32]);
        let signature = key_pair.sign(b"transcript");
        // Ed25519 (0x0807) is accepted although no browser hello offers it.
        verify_signature(&certificate, 0x0807, b"transcript", signature.as_ref()).unwrap();
        assert!(verify_signature(&certificate, 0x0807, b"other", signature.as_ref()).is_err());
        // A scheme that does not fit the key, and one TLS 1.3 forbids.
        assert!(verify_signature(&certificate, 0x0403, b"transcript", signature.as_ref()).is_err());
        assert!(verify_signature(&certificate, 0x0401, b"transcript", signature.as_ref()).is_err());
        assert!(
            verify_signature(&[0x30, 0x00], 0x0807, b"transcript", signature.as_ref()).is_err()
        );
    }

    #[test]
    fn der_lengths_are_bounds_checked() {
        assert_eq!(
            element(&[0x04, 0x02, 1, 2, 3]),
            Some((0x04, &[1u8, 2][..], &[3u8][..]))
        );
        assert_eq!(
            element(&[0x04, 0x81, 0x01, 9]),
            Some((0x04, &[9u8][..], &[][..]))
        );
        // Truncated contents, truncated length, indefinite length.
        assert_eq!(element(&[0x04, 0x02, 1]), None);
        assert_eq!(element(&[0x04, 0x82, 0x01]), None);
        assert_eq!(element(&[0x04, 0x80]), None);
        assert_eq!(element(&[0x04]), None);
    }

    /// A CompressedCertificate body around `message` compressed by `algorithm`.
    fn compressed(algorithm: u16, announced_len: usize, data: &[u8]) -> Vec<u8> {
        let mut body = algorithm.to_be_bytes().to_vec();
        body.extend_from_slice(&(announced_len as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(data);
        body
    }

    #[test]
    fn compressed_certificates_decompress_to_the_announced_length() {
        let message = b"certificate message ".repeat(40);
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(&message).unwrap();
        let zlib = zlib.finish().unwrap();

        assert_eq!(
            decompress(&compressed(1, message.len(), &zlib)).unwrap(),
            message
        );
        // RFC 8879, Section 4: a length mismatch aborts the handshake.
        assert!(decompress(&compressed(1, message.len() - 1, &zlib)).is_err());
        assert!(decompress(&compressed(1, message.len() + 1, &zlib)).is_err());
        assert!(decompress(&compressed(1, MAX_DECOMPRESSED_LEN + 1, &zlib)).is_err());
        assert!(decompress(&compressed(9, message.len(), &zlib)).is_err());
        assert!(decompress(&compressed(2, message.len(), b"not brotli")).is_err());
        assert!(decompress(&[0, 1, 0]).is_err());

        // Brotli: the stream for an empty input is a single 0x06 byte, and
        // zstd: an empty frame.
        assert!(decompress(&compressed(2, 0, &[0x06])).unwrap().is_empty());
        let zstd_empty = [
            0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51,
        ];
        assert!(decompress(&compressed(3, 0, &zstd_empty))
            .unwrap()
            .is_empty());
    }
}
