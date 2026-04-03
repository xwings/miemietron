use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tracing::debug;

use super::fingerprint::{self, TlsFingerprint};

// ---------------------------------------------------------------------------
// Options struct (used by proxy adapters)
// ---------------------------------------------------------------------------

/// Configuration for a TLS connection.
#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub sni: String,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
}

/// Convenience function: wrap an existing async stream with a TLS client
/// handshake using `TlsOptions`.
pub async fn wrap_tls<S>(stream: S, opts: &TlsOptions) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connector = TlsConnector::new(
        opts.sni.clone(),
        opts.skip_cert_verify,
        opts.alpn.clone(),
        opts.fingerprint.clone(),
    )?;
    connector.connect(stream).await
}

// ---------------------------------------------------------------------------
// TlsConnector - reusable, shareable TLS connector
// ---------------------------------------------------------------------------

/// TLS transport layer wrapping `tokio_rustls::TlsConnector`.
///
/// Supports configurable SNI, ALPN, and optional certificate-verification
/// bypass (dangerous, but required by some proxy configurations such as
/// self-signed certs behind a CDN).
pub struct TlsConnector {
    inner: tokio_rustls::TlsConnector,
    sni: ServerName<'static>,
}

impl TlsConnector {
    /// Create a new TLS connector.
    ///
    /// * `sni` -- Server Name Indication hostname.
    /// * `skip_cert_verify` -- Accept any server certificate (insecure).
    /// * `alpn` -- ALPN protocol strings (e.g. `["h2", "http/1.1"]`).
    /// * `fingerprint_str` -- Browser fingerprint name (e.g. `"chrome"`).
    pub fn new(
        sni: String,
        skip_cert_verify: bool,
        alpn: Vec<String>,
        fingerprint_str: Option<String>,
    ) -> Result<Self> {
        let server_name: ServerName<'static> = ServerName::try_from(sni.clone())
            .map_err(|e| anyhow::anyhow!("invalid SNI '{}': {}", sni, e))?
            .to_owned();

        // Parse the fingerprint and build a customised CryptoProvider.
        let fp = TlsFingerprint::from_str_opt(fingerprint_str.as_deref());
        let provider = fingerprint::make_crypto_provider(fp);

        let mut config = if skip_cert_verify {
            debug!(
                "TLS: skip_cert_verify enabled for {}, fingerprint={}",
                sni, fp
            );
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow::anyhow!("TLS protocol version error: {}", e))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier::new()))
                .with_no_client_auth()
        } else {
            debug!("TLS: fingerprint={} for {}", fp, sni);
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow::anyhow!("TLS protocol version error: {}", e))?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Use browser-matching ALPN if configured fingerprint provides
        // defaults and the caller didn't specify any.
        let effective_alpn = if alpn.is_empty() {
            fingerprint::default_alpn_for(fp)
        } else {
            alpn
        };

        if !effective_alpn.is_empty() {
            config.alpn_protocols = effective_alpn.into_iter().map(|s| s.into_bytes()).collect();
        }

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        Ok(Self {
            inner: connector,
            sni: server_name,
        })
    }

    /// Perform the TLS handshake over an existing async stream.
    pub async fn connect<S>(&self, stream: S) -> Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let tls_stream = self
            .inner
            .connect(self.sni.clone(), stream)
            .await
            .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;
        Ok(tls_stream)
    }
}

// ---------------------------------------------------------------------------
// Dangerous: accept-anything certificate verifier
// ---------------------------------------------------------------------------

/// A `ServerCertVerifier` that blindly accepts any certificate chain.
///
/// This is intentionally insecure and exists only because some proxy
/// configurations (e.g. self-signed certs behind a CDN, Reality transport)
/// require it.
#[derive(Debug)]
pub(crate) struct NoVerifier {
    /// Signature schemes derived from the ring crypto provider so the list
    /// stays in sync with what rustls can actually negotiate.
    schemes: Vec<SignatureScheme>,
}

impl NoVerifier {
    pub(crate) fn new() -> Self {
        let schemes = default_provider()
            .signature_verification_algorithms
            .supported_schemes();
        Self { schemes }
    }
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}
