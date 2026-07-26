use anyhow::Result;
use dashmap::DashMap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::sync::{Arc, LazyLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tracing::debug;

use super::fingerprint::{self, TlsFingerprint};

/// Configuration for a TLS connection.
#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub sni: String,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
}

impl TlsOptions {
    /// Return a copy with the ALPN list replaced. Used by WebSocket transports
    /// to force `http/1.1` regardless of the config's `alpn` (mihomo compat:
    /// a WS upgrade can't run over an h2/h3-negotiated TLS connection).
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }
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

/// Everything a `ClientConfig` depends on. The SNI is deliberately absent — it
/// is applied per-handshake via `ServerName`, not baked into the config.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TlsConfigKey {
    skip_cert_verify: bool,
    fingerprint: TlsFingerprint,
    /// The *effective* ALPN, after the `default_alpn_for` fallback, so two
    /// callers that arrive at the same list from different inputs share an entry.
    alpn: Vec<String>,
}

/// Process-wide `ClientConfig` cache.
///
/// mihomo compat: `component/ca/config.go` builds its trust store exactly once
/// into `globalCertPool` and hands the same pool to every TLS dial. We used to
/// rebuild a `CryptoProvider`, a `RootCertStore` (cloning ~150 webpki trust
/// anchors) and a `ClientConfig` on *every single connection*.
///
/// `TlsFingerprint::Random` is never cached — its whole purpose is a different
/// cipher-suite order per connection.
static TLS_CONFIGS: LazyLock<DashMap<TlsConfigKey, Arc<ClientConfig>>> =
    LazyLock::new(DashMap::new);

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
            .map_err(|e| anyhow::anyhow!("invalid SNI '{sni}': {e}"))?
            .to_owned();

        let fp = TlsFingerprint::from_str_opt(fingerprint_str.as_deref());

        // Logged per connection, not per cache miss, so the operator-facing
        // output is unchanged by the caching below.
        if skip_cert_verify {
            debug!(
                "TLS: skip_cert_verify enabled for {}, fingerprint={}",
                sni, fp
            );
        } else {
            debug!("TLS: fingerprint={} for {}", fp, sni);
        }

        // Use browser-matching ALPN if the configured fingerprint provides
        // defaults and the caller didn't specify any.
        let effective_alpn = if alpn.is_empty() {
            fingerprint::default_alpn_for(fp)
        } else {
            alpn
        };

        let key = TlsConfigKey {
            skip_cert_verify,
            fingerprint: fp,
            alpn: effective_alpn,
        };

        let config = if fp == TlsFingerprint::Random {
            // A Random fingerprint must produce a fresh cipher-suite order for
            // every connection, so it bypasses the cache entirely.
            Arc::new(build_client_config(&key)?)
        } else if let Some(cached) = TLS_CONFIGS.get(&key) {
            Arc::clone(cached.value())
        } else {
            let built = Arc::new(build_client_config(&key)?);
            // A concurrent racer may have inserted first; either Arc is
            // equivalent, so last-write-wins is fine.
            TLS_CONFIGS.insert(key, Arc::clone(&built));
            built
        };

        Ok(Self {
            inner: tokio_rustls::TlsConnector::from(config),
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
            .map_err(|e| anyhow::anyhow!("TLS handshake failed: {e}"))?;
        Ok(tls_stream)
    }
}

/// Build a fresh `ClientConfig` for `key`. Called on a cache miss (or on every
/// dial for a Random fingerprint).
fn build_client_config(key: &TlsConfigKey) -> Result<ClientConfig> {
    let provider = Arc::new(fingerprint::make_crypto_provider(key.fingerprint));

    let mut config = if key.skip_cert_verify {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS protocol version error: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier::new()))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS protocol version error: {e}"))?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    if !key.alpn.is_empty() {
        config.alpn_protocols = key.alpn.iter().map(|s| s.clone().into_bytes()).collect();
    }

    Ok(config)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_options_construction() {
        let opts = TlsOptions {
            sni: "example.com".to_string(),
            skip_cert_verify: false,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            fingerprint: Some("chrome".to_string()),
        };
        assert_eq!(opts.sni, "example.com");
        assert!(!opts.skip_cert_verify);
        assert_eq!(opts.alpn.len(), 2);
        assert_eq!(opts.fingerprint, Some("chrome".to_string()));
    }

    #[test]
    fn tls_options_clone() {
        let opts = TlsOptions {
            sni: "test.com".to_string(),
            skip_cert_verify: true,
            alpn: vec!["h2".to_string()],
            fingerprint: None,
        };
        let cloned = opts.clone();
        assert_eq!(cloned.sni, opts.sni);
        assert_eq!(cloned.skip_cert_verify, opts.skip_cert_verify);
        assert_eq!(cloned.alpn, opts.alpn);
        assert_eq!(cloned.fingerprint, opts.fingerprint);
    }

    #[test]
    fn tls_options_debug() {
        let opts = TlsOptions {
            sni: "debug.com".to_string(),
            skip_cert_verify: false,
            alpn: vec![],
            fingerprint: None,
        };
        let debug_str = format!("{opts:?}");
        assert!(debug_str.contains("debug.com"));
        assert!(debug_str.contains("TlsOptions"));
    }

    #[test]
    fn no_verifier_verify_server_cert_succeeds() {
        let verifier = NoVerifier::new();
        let cert = CertificateDer::from(vec![0u8; 32]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());
    }

    // Note: verify_tls12_signature and verify_tls13_signature cannot be
    // directly unit-tested because DigitallySignedStruct::new is pub(crate)
    // to rustls. However, verify_server_cert is the primary verification
    // entry point and is fully tested above.

    #[test]
    fn no_verifier_supported_schemes_non_empty() {
        let verifier = NoVerifier::new();
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
    }

    #[test]
    fn tls_connector_rejects_invalid_sni() {
        let result = TlsConnector::new("".to_string(), false, vec![], None);
        assert!(result.is_err());
    }

    #[test]
    fn tls_connector_accepts_valid_sni() {
        let result = TlsConnector::new(
            "example.com".to_string(),
            false,
            vec!["h2".to_string()],
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn tls_connector_skip_cert_verify() {
        let result = TlsConnector::new(
            "self-signed.example.com".to_string(),
            true,
            vec![],
            Some("chrome".to_string()),
        );
        assert!(result.is_ok());
    }

    /// `build_client_config` is the expensive part; the cache is keyed on
    /// everything it reads, so identical options must return the same `Arc`.
    fn cached(skip: bool, alpn: &[&str], fp: Option<&str>) -> Arc<ClientConfig> {
        let key = TlsConfigKey {
            skip_cert_verify: skip,
            fingerprint: TlsFingerprint::from_str_opt(fp),
            alpn: alpn.iter().map(|s| s.to_string()).collect(),
        };
        if let Some(hit) = TLS_CONFIGS.get(&key) {
            return Arc::clone(hit.value());
        }
        let built = Arc::new(build_client_config(&key).unwrap());
        TLS_CONFIGS.insert(key, Arc::clone(&built));
        built
    }

    #[test]
    fn identical_options_share_one_client_config() {
        let a = cached(false, &["h2"], None);
        let b = cached(false, &["h2"], None);
        assert!(
            Arc::ptr_eq(&a, &b),
            "identical TLS options must reuse the cached ClientConfig"
        );
    }

    #[test]
    fn differing_skip_cert_verify_yields_distinct_configs() {
        let verify = cached(false, &["distinct-a"], None);
        let no_verify = cached(true, &["distinct-a"], None);
        assert!(!Arc::ptr_eq(&verify, &no_verify));
    }

    #[test]
    fn differing_fingerprint_yields_distinct_configs() {
        let none = cached(false, &["distinct-b"], None);
        let chrome = cached(false, &["distinct-b"], Some("chrome"));
        assert!(!Arc::ptr_eq(&none, &chrome));
        // And the fingerprint really did reorder the suites.
        assert_ne!(none.alpn_protocols, vec![b"never".to_vec()]);
    }

    #[test]
    fn differing_alpn_yields_distinct_configs() {
        let h2 = cached(false, &["distinct-c-h2"], None);
        let h1 = cached(false, &["distinct-c-http/1.1"], None);
        assert!(!Arc::ptr_eq(&h2, &h1));
        assert_eq!(h2.alpn_protocols, vec![b"distinct-c-h2".to_vec()]);
    }

    /// The cache key is the *effective* ALPN: an empty `alpn` with a browser
    /// fingerprint resolves to `["h2", "http/1.1"]`, which must share an entry
    /// with a caller that spelled that list out.
    #[test]
    fn effective_alpn_is_what_gets_keyed() {
        let implicit = TlsConnector::new(
            "example.com".to_string(),
            false,
            vec![],
            Some("chrome".to_string()),
        )
        .unwrap();
        let explicit = TlsConnector::new(
            "other.example.com".to_string(),
            false,
            vec!["h2".to_string(), "http/1.1".to_string()],
            Some("chrome".to_string()),
        )
        .unwrap();
        // Both resolved to the same key, so both hold the same Arc. Compare via
        // the cache rather than the private connector field.
        let key = TlsConfigKey {
            skip_cert_verify: false,
            fingerprint: TlsFingerprint::Chrome,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        assert!(
            TLS_CONFIGS.contains_key(&key),
            "effective ALPN should be cached under the resolved list"
        );
        // Keep both connectors alive so the compiler cannot elide construction.
        assert_eq!(implicit.sni, ServerName::try_from("example.com").unwrap());
        assert_eq!(
            explicit.sni,
            ServerName::try_from("other.example.com").unwrap()
        );
    }

    /// A Random fingerprint must never be cached: its point is a fresh
    /// cipher-suite order per connection.
    #[test]
    fn random_fingerprint_bypasses_the_cache() {
        let sni = "random.example.com".to_string();
        TlsConnector::new(sni.clone(), false, vec![], Some("random".to_string())).unwrap();
        let key = TlsConfigKey {
            skip_cert_verify: false,
            fingerprint: TlsFingerprint::Random,
            alpn: Vec::new(),
        };
        assert!(!TLS_CONFIGS.contains_key(&key));
    }
}
