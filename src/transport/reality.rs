//! VLESS Reality transport.
//!
//! Reality makes proxy traffic indistinguishable from a legitimate TLS
//! connection to a camouflage website (e.g. `www.microsoft.com`).  The
//! client performs a real TLS handshake with the proxy server using the
//! camouflage SNI.  Authentication is performed out-of-band via an
//! x25519 shared secret embedded in the TLS session ID.
//!
//! After the TLS connection is established the client sends a Reality
//! authentication header in the first application-data record.  The
//! server verifies the HMAC and then proxies data normally.
//!
//! # Wire format of the Reality auth header
//!
//! ```text
//! [ client_public_key: 32 bytes ]
//! [ timestamp:          8 bytes (big-endian unix seconds) ]
//! [ short_id_len:       1 byte  ]
//! [ short_id:           variable ]
//! [ hmac:              32 bytes (HMAC-SHA256) ]
//! ```

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::client::TlsStream;
use tracing::debug;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::fingerprint::{self, TlsFingerprint};
use super::tls::TlsOptions;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for a Reality connection, parsed from proxy config.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Server's x25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Short ID used to identify the client to the server (hex-decoded).
    pub short_id: Vec<u8>,
    /// Camouflage SNI (e.g. "www.microsoft.com").
    pub server_name: String,
    /// TLS fingerprint to use for the ClientHello.
    pub fingerprint: TlsFingerprint,
}

impl RealityConfig {
    /// Parse a `RealityConfig` from proxy configuration fields.
    ///
    /// `public_key_b64` is base64-encoded, `short_id_hex` is hex-encoded,
    /// `server_name` is the camouflage SNI, and `fingerprint` is the
    /// browser fingerprint string.
    pub fn from_opts(
        public_key_b64: &str,
        short_id_hex: &str,
        server_name: String,
        fingerprint: TlsFingerprint,
    ) -> Result<Self> {
        // The public key is typically base64-encoded in config files.
        let pk_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            public_key_b64.trim(),
        )
        .context("Reality: invalid base64 public key")?;

        if pk_bytes.len() != 32 {
            anyhow::bail!(
                "Reality: public key must be 32 bytes, got {}",
                pk_bytes.len()
            );
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pk_bytes);

        let short_id = hex::decode(short_id_hex.trim()).context("Reality: invalid hex short_id")?;

        Ok(Self {
            public_key,
            short_id,
            server_name,
            fingerprint,
        })
    }
}

// ---------------------------------------------------------------------------
// Auth header construction
// ---------------------------------------------------------------------------

/// Build the Reality authentication header.
///
/// This is sent as the first application-data record after the TLS
/// handshake completes.  The server verifies the HMAC to authenticate
/// the client without any additional round-trip.
fn build_auth_header(
    client_public: &[u8; 32],
    shared_secret: &[u8; 32],
    short_id: &[u8],
) -> Vec<u8> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Derive auth key: HMAC-SHA256(shared_secret, "Reality")
    let mut auth_mac =
        HmacSha256::new_from_slice(shared_secret).expect("HMAC accepts any key size");
    auth_mac.update(b"Reality");
    let auth_key = auth_mac.finalize().into_bytes();

    // Compute HMAC over (client_public || timestamp || short_id)
    let mut hmac = HmacSha256::new_from_slice(&auth_key).expect("HMAC accepts any key size");
    hmac.update(client_public);
    hmac.update(&timestamp.to_be_bytes());
    hmac.update(short_id);
    let tag = hmac.finalize().into_bytes();

    // Assemble the header
    let mut header = Vec::with_capacity(32 + 8 + 1 + short_id.len() + 32);
    header.extend_from_slice(client_public);
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.push(short_id.len() as u8);
    header.extend_from_slice(short_id);
    header.extend_from_slice(&tag);
    header
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Establish a Reality connection over a raw TCP stream.
///
/// 1. Performs a genuine TLS handshake with the camouflage SNI and the
///    configured browser fingerprint.
/// 2. Generates an ephemeral x25519 keypair and computes the shared
///    secret with the server's public key.
/// 3. Sends the Reality authentication header in the first TLS record.
/// 4. Returns the authenticated TLS stream ready for proxy protocol
///    framing (VLESS/Trojan).
pub async fn wrap_reality<S>(stream: S, config: &RealityConfig) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!(
        "Reality: connecting with SNI={}, fingerprint={}",
        config.server_name, config.fingerprint
    );

    // --- Step 1: x25519 key exchange ---
    let client_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);
    let server_public = PublicKey::from(config.public_key);
    let shared_secret = client_secret.diffie_hellman(&server_public);

    // --- Step 2: TLS handshake with camouflage SNI and fingerprint ---
    let fp = config.fingerprint;
    let provider = fingerprint::make_crypto_provider(fp);

    // Determine ALPN: use browser-matching defaults for Reality since
    // the camouflage site expects normal browser behaviour.
    let alpn = fingerprint::default_alpn_for(fp);

    let tls_opts = TlsOptions {
        sni: config.server_name.clone(),
        skip_cert_verify: true, // Server uses camouflage cert, not its own
        alpn,
        fingerprint: Some(config.fingerprint.to_string()),
    };

    // Build rustls ClientConfig with the fingerprinted provider
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("Reality: TLS version config error: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(super::tls::NoVerifier::new()))
        .with_no_client_auth();

    let mut tls_config = tls_config;
    if !tls_opts.alpn.is_empty() {
        tls_config.alpn_protocols = tls_opts
            .alpn
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    }

    let server_name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
        .map_err(|e| anyhow::anyhow!("Reality: invalid SNI '{}': {}", config.server_name, e))?
        .to_owned();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| anyhow::anyhow!("Reality: TLS handshake failed: {}", e))?;

    // --- Step 3: Send Reality auth header ---
    let auth_header = build_auth_header(
        client_public.as_bytes(),
        shared_secret.as_bytes(),
        &config.short_id,
    );

    tls_stream
        .write_all(&auth_header)
        .await
        .context("Reality: failed to send auth header")?;
    tls_stream
        .flush()
        .await
        .context("Reality: failed to flush auth header")?;

    // --- Step 4: Read server acknowledgment ---
    // The server responds with a single byte: 0x00 = success.
    let mut ack = [0u8; 1];
    tls_stream
        .read_exact(&mut ack)
        .await
        .context("Reality: failed to read server acknowledgment")?;

    if ack[0] != 0x00 {
        anyhow::bail!(
            "Reality: server rejected authentication (code: 0x{:02x})",
            ack[0]
        );
    }

    debug!("Reality: authenticated successfully");
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_structure() {
        let client_pub = [0xAA; 32];
        let shared_secret = [0xBB; 32];
        let short_id = vec![0x01, 0x02, 0x03, 0x04];

        let header = build_auth_header(&client_pub, &shared_secret, &short_id);

        // client_public (32) + timestamp (8) + short_id_len (1) + short_id (4) + hmac (32)
        assert_eq!(header.len(), 32 + 8 + 1 + 4 + 32);

        // Verify client public key is at the start
        assert_eq!(&header[..32], &[0xAA; 32]);

        // Verify short_id_len
        assert_eq!(header[40], 4);

        // Verify short_id
        assert_eq!(&header[41..45], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn auth_header_empty_short_id() {
        let client_pub = [0x00; 32];
        let shared_secret = [0xFF; 32];
        let short_id = vec![];

        let header = build_auth_header(&client_pub, &shared_secret, &short_id);
        // 32 + 8 + 1 + 0 + 32 = 73
        assert_eq!(header.len(), 73);
        assert_eq!(header[40], 0); // short_id_len = 0
    }

    #[test]
    fn config_from_opts_valid() {
        // 32 zero bytes base64-encoded
        let pk_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[0u8; 32]);
        let config = RealityConfig::from_opts(
            &pk_b64,
            "aabbccdd",
            "www.example.com".to_string(),
            TlsFingerprint::Chrome,
        )
        .unwrap();

        assert_eq!(config.public_key, [0u8; 32]);
        assert_eq!(config.short_id, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(config.server_name, "www.example.com");
        assert_eq!(config.fingerprint, TlsFingerprint::Chrome);
    }

    #[test]
    fn config_from_opts_bad_key_length() {
        let pk_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &[0u8; 16], // wrong length
        );
        let result = RealityConfig::from_opts(
            &pk_b64,
            "00",
            "example.com".to_string(),
            TlsFingerprint::None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn config_from_opts_bad_hex() {
        let pk_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[0u8; 32]);
        let result = RealityConfig::from_opts(
            &pk_b64,
            "ZZZZ", // invalid hex
            "example.com".to_string(),
            TlsFingerprint::None,
        );
        assert!(result.is_err());
    }
}
