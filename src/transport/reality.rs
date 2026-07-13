//! Mihomo-compatible REALITY client transport.
//!
//! REALITY authentication is carried inside the TLS 1.3 ClientHello session
//! ID. It is not an application-data header and has no acknowledgement byte.
//! The TLS implementation used here exposes the key-share and ClientHello hook
//! needed to implement the same wire flow as mihomo/Xray.

use anyhow::{Context, Result};
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::RealityConfig as RustlsRealityConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tracing::debug;

use super::fingerprint::{self, TlsFingerprint};

/// REALITY protocol version sent by current mihomo Meta.
const MIHOMO_REALITY_VERSION: [u8; 3] = [1, 8, 2];
const MAX_SHORT_ID_LEN: usize = 8;

/// Runtime-only configuration for a REALITY connection.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Server's X25519 public key.
    pub public_key: [u8; 32],
    /// Client short ID, zero-padded exactly as mihomo does.
    pub short_id: [u8; MAX_SHORT_ID_LEN],
    /// Camouflage SNI.
    pub server_name: String,
    /// Requested ClientHello fingerprint family.
    pub fingerprint: TlsFingerprint,
    /// ALPN values to place in the ClientHello.
    pub alpn: Vec<String>,
}

impl RealityConfig {
    /// Parse mihomo `reality-opts` without retaining encoded config strings.
    pub fn from_opts(
        public_key_b64: &str,
        short_id_hex: &str,
        server_name: String,
        fingerprint: TlsFingerprint,
        alpn: Vec<String>,
        support_x25519mlkem768: bool,
    ) -> Result<Self> {
        if support_x25519mlkem768 {
            anyhow::bail!(
                "REALITY: support-x25519mlkem768 is not implemented; refusing to downgrade silently"
            );
        }
        if fingerprint == TlsFingerprint::None {
            anyhow::bail!("REALITY: a supported client-fingerprint is required");
        }

        // Mihomo uses base64.RawURLEncoding: URL-safe alphabet, no padding.
        let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key_b64.trim())
            .context("REALITY: invalid raw URL-safe Base64 public key")?;
        let public_key: [u8; 32] = pk_bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "REALITY: public key must decode to 32 bytes, got {}",
                bytes.len()
            )
        })?;

        let decoded_short_id =
            hex::decode(short_id_hex.trim()).context("REALITY: invalid hexadecimal short-id")?;
        if decoded_short_id.len() > MAX_SHORT_ID_LEN {
            anyhow::bail!(
                "REALITY: short-id must be at most {MAX_SHORT_ID_LEN} bytes, got {}",
                decoded_short_id.len()
            );
        }
        let mut short_id = [0u8; MAX_SHORT_ID_LEN];
        short_id[..decoded_short_id.len()].copy_from_slice(&decoded_short_id);

        Ok(Self {
            public_key,
            short_id,
            server_name,
            fingerprint,
            alpn,
        })
    }
}

/// Inner verifier used by rustls's REALITY verifier.
///
/// The fork first authenticates a REALITY certificate using
/// HMAC-SHA512(auth_key, Ed25519 public key), then delegates non-REALITY
/// certificates to this verifier. Always rejecting here makes successful TLS
/// synonymous with successful REALITY authentication; a camouflage site's
/// ordinary valid certificate must never be accepted as the proxy server.
#[derive(Debug)]
struct RealityOnlyVerifier {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for RealityOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// Establish a REALITY-authenticated TLS 1.3 stream.
pub async fn wrap_reality<S>(stream: S, config: &RealityConfig) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!(
        "REALITY: connecting with SNI={}, fingerprint={}",
        config.server_name, config.fingerprint
    );

    let provider = fingerprint::make_crypto_provider(config.fingerprint);
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let reality = RustlsRealityConfig::new(config.public_key, config.short_id.to_vec())
        .context("REALITY: invalid protocol configuration")?
        .with_client_version(MIHOMO_REALITY_VERSION);

    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("REALITY: TLS version configuration failed: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RealityOnlyVerifier { schemes }))
        .with_reality(reality)
        .with_no_client_auth();

    tls_config.alpn_protocols = config
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    tls_config.resumption = rustls::client::Resumption::disabled();

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|error| anyhow::anyhow!("REALITY: invalid SNI: {error}"))?
        .to_owned();

    let tls_stream = tokio_rustls::TlsConnector::from(Arc::new(tls_config))
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            anyhow::anyhow!("REALITY: TLS handshake/authentication failed: {error}")
        })?;

    debug!("REALITY: authentication succeeded");
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::Sha256;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn encoded_key(bytes: [u8; 32]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn config(public_key: [u8; 32], short_id: &str) -> RealityConfig {
        RealityConfig::from_opts(
            &encoded_key(public_key),
            short_id,
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec!["h2".to_string(), "http/1.1".to_string()],
            false,
        )
        .unwrap()
    }

    #[test]
    fn parses_raw_urlsafe_public_key_and_pads_short_id() {
        let parsed = config([0xff; 32], "a1b2c3");
        assert_eq!(parsed.public_key, [0xff; 32]);
        assert_eq!(parsed.short_id, [0xa1, 0xb2, 0xc3, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_padded_or_standard_base64() {
        let padded = format!("{}=", encoded_key([0xff; 32]));
        assert!(RealityConfig::from_opts(
            &padded,
            "",
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec![],
            false,
        )
        .is_err());

        let standard = base64::engine::general_purpose::STANDARD.encode([0xff; 32]);
        assert!(RealityConfig::from_opts(
            &standard,
            "",
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec![],
            false,
        )
        .is_err());
    }

    #[test]
    fn validates_short_id_and_hybrid_option() {
        assert!(RealityConfig::from_opts(
            &encoded_key([1; 32]),
            "001122334455667788",
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec![],
            false,
        )
        .is_err());
        assert!(RealityConfig::from_opts(
            &encoded_key([1; 32]),
            "not-hex",
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec![],
            false,
        )
        .is_err());
        assert!(RealityConfig::from_opts(
            &encoded_key([1; 32]),
            "",
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec![],
            true,
        )
        .is_err());
    }

    #[tokio::test]
    async fn client_hello_contains_mihomo_reality_session_id() {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "01020304");
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let client = tokio::spawn(async move { wrap_reality(client_io, &config).await });

        let mut record_header = [0u8; 5];
        server_io.read_exact(&mut record_header).await.unwrap();
        assert_eq!(record_header[0], 0x16);
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let mut hello = vec![0u8; record_len];
        server_io.read_exact(&mut hello).await.unwrap();

        assert_eq!(hello[0], 0x01);
        assert_eq!(hello[38], 32);
        let client_random: [u8; 32] = hello[6..38].try_into().unwrap();
        let encrypted_session_id = &hello[39..71];
        assert_ne!(encrypted_session_id, &[0u8; 32]);

        let client_public = extract_x25519_key_share(&hello).unwrap();
        let shared_secret = server_secret
            .diffie_hellman(&PublicKey::from(client_public))
            .to_bytes();
        let auth_key = hkdf::Hkdf::<Sha256>::new(Some(&client_random[..20]), &shared_secret);
        let mut key = [0u8; 32];
        auth_key.expand(b"REALITY", &mut key).unwrap();

        let mut aad = hello.clone();
        aad[39..71].fill(0);
        let plaintext = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&client_random[20..]),
                Payload {
                    msg: encrypted_session_id,
                    aad: &aad,
                },
            )
            .unwrap();

        assert_eq!(&plaintext[..3], &MIHOMO_REALITY_VERSION);
        let timestamp = u32::from_be_bytes(plaintext[4..8].try_into().unwrap()) as u64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(timestamp.abs_diff(now) <= 5);
        assert_eq!(&plaintext[8..], &[1, 2, 3, 4, 0, 0, 0, 0]);

        drop(server_io);
        assert!(client.await.unwrap().is_err());
    }

    fn extract_x25519_key_share(hello: &[u8]) -> Option<[u8; 32]> {
        let mut offset = 39 + hello[38] as usize;
        let suites_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2 + suites_len;
        let compression_len = hello[offset] as usize;
        offset += 1 + compression_len;
        let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let extensions_end = offset + extensions_len;

        while offset + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
            let extension_len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
            offset += 4;
            if extension_type == 0x0033 && extension_len >= 38 {
                let data = &hello[offset..offset + extension_len];
                if u16::from_be_bytes([data[2], data[3]]) == 0x001d
                    && u16::from_be_bytes([data[4], data[5]]) == 32
                {
                    return data[6..38].try_into().ok();
                }
            }
            offset += extension_len;
        }
        None
    }
}
