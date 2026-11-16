//! Mihomo-compatible REALITY client transport.
//!
//! REALITY authentication is carried inside the TLS 1.3 ClientHello session
//! ID. It is not an application-data header and has no acknowledgement byte.
//! The TLS implementation used here exposes the key-share and ClientHello hook
//! needed to implement the same wire flow as mihomo/Xray.
//!
//! `support-x25519mlkem768` picks between two ClientHello flavours:
//!
//! * off — a lone X25519 key share. The rustls fork's `with_reality` hook
//!   generates the share and seals the session ID itself.
//! * on — X25519MLKEM768 followed by X25519, which XTLS/REALITY servers insist
//!   on since their commit 8cdf7bf (2026-09). The fork's hook cannot emit a
//!   second share, so this flavour is driven from here: see [`connect_hybrid`].

use anyhow::{Context, Result};
use base64::Engine as _;
use ring::{aead, hkdf};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::reality::RealityServerCertVerifier;
use rustls::client::RealityConfig as RustlsRealityConfig;
use rustls::crypto::{ActiveKeyExchange, GetRandomFailed, SecureRandom, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, DigitallySignedStruct, Error as TlsError, NamedGroup, ProtocolVersion,
    SignatureScheme,
};
use std::cell::RefCell;
use std::ops::Range;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tracing::debug;

use super::fingerprint::{self, TlsFingerprint};
use super::x25519mlkem768::HybridKeyShare;

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
    /// Offer the X25519MLKEM768 hybrid key share ahead of X25519.
    pub x25519mlkem768: bool,
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
            // mihomo compat: `support-x25519mlkem768` only stops reality.go
            // from stripping the hybrid share out of the uTLS preset
            // (`BuildRemovedX25519MLKEM768HandshakeState`). A preset that has
            // none to begin with sends X25519 alone whatever the flag says.
            x25519mlkem768: support_x25519mlkem768 && fingerprint.has_x25519mlkem768(),
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

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|error| anyhow::anyhow!("REALITY: invalid SNI: {error}"))?
        .to_owned();

    let connect = if config.x25519mlkem768 {
        connect_hybrid(stream, config, server_name)?
    } else {
        let tls_config = client_config(config, None)?;
        tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(server_name, stream)
    };
    let tls_stream = connect.await.map_err(|error| {
        anyhow::anyhow!("REALITY: TLS handshake/authentication failed: {error}")
    })?;

    // mihomo compat: reality.go logs whether the server settled on the hybrid
    // key exchange.
    let group = tls_stream.get_ref().1.negotiated_key_exchange_group();
    debug!(
        "REALITY: authentication succeeded, using X25519MLKEM768: {}",
        group.is_some_and(|group| group.name() == NamedGroup::X25519MLKEM768)
    );
    Ok(tls_stream)
}

/// Where the hybrid flavour hands its auth key to the certificate verifier.
type AuthKeySlot = Arc<Mutex<Option<[u8; 32]>>>;

/// The rustls config for one handshake.
///
/// `hybrid_auth_key` picks the flavour. `None`: the fork's `with_reality` hook
/// does the X25519 key share, the session ID and the certificate check.
/// `Some`: stock rustls with [`HybridGroup`] first, for [`connect_hybrid`] to
/// drive, and the fork's verifier reading the auth key from the given slot.
fn client_config(
    config: &RealityConfig,
    hybrid_auth_key: Option<&AuthKeySlot>,
) -> Result<rustls::ClientConfig> {
    let mut provider = fingerprint::make_crypto_provider(config.fingerprint);
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let reject_all = Arc::new(RealityOnlyVerifier { schemes });
    if hybrid_auth_key.is_some() {
        provider.kx_groups.insert(0, &HybridGroup);
        provider.secure_random = &ScriptedRandom;
    }

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("REALITY: TLS version configuration failed: {error}"))?
        .dangerous();
    let mut tls_config = match hybrid_auth_key {
        None => {
            let reality = RustlsRealityConfig::new(config.public_key, config.short_id.to_vec())
                .context("REALITY: invalid protocol configuration")?
                .with_client_version(MIHOMO_REALITY_VERSION);
            builder
                .with_custom_certificate_verifier(reject_all)
                .with_reality(reality)
                .with_no_client_auth()
        }
        Some(auth_key) => builder
            .with_custom_certificate_verifier(RealityServerCertVerifier::new(
                auth_key.clone(),
                reject_all,
            ))
            .with_no_client_auth(),
    };

    tls_config.alpn_protocols = config
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    tls_config.resumption = rustls::client::Resumption::disabled();
    Ok(tls_config)
}

// ---------------------------------------------------------------------------
// Hybrid (X25519MLKEM768 + X25519) ClientHello
// ---------------------------------------------------------------------------
//
// The session ID authenticates the whole ClientHello — the hello is the AEAD's
// associated data — so the hello has to exist before its own session ID can be
// computed. rustls offers no hook for that beyond the fork's X25519-only one,
// but its ClientHello is a pure function of the config, the key share and the
// bytes it draws from the provider's random source. So the hello is built
// twice from the same inputs: once to learn its bytes, then again with the
// sealed session ID substituted for the random one rustls drew the first time.
//
// Both rustls hooks involved (`CryptoProvider::secure_random` and
// `kx_groups`) must be `&'static`, so the per-connection inputs reach them
// through a thread-local. It is set only inside `build_scripted`, around a
// synchronous call, which is why no other connection can ever observe it.

thread_local! {
    static HELLO_SCRIPT: RefCell<Option<HelloScript>> = const { RefCell::new(None) };
}

/// The inputs rustls reads while it builds one hybrid ClientHello.
struct HelloScript {
    key_share: HybridKeyShare,
    /// Every byte rustls drew from the random source, in order.
    random: Vec<u8>,
    /// Read position in `random` when replaying it; `None` while recording.
    replay: Option<usize>,
}

/// Run `build` with `script` installed for [`HybridGroup`] and
/// [`ScriptedRandom`] to read, and hand the script back afterwards.
fn build_scripted<T>(script: HelloScript, build: impl FnOnce() -> T) -> (T, HelloScript) {
    /// Clears the script even if `build` unwinds, so key material can never
    /// leak into a later handshake on this thread.
    struct Uninstall;
    impl Drop for Uninstall {
        fn drop(&mut self) {
            HELLO_SCRIPT.take();
        }
    }

    HELLO_SCRIPT.set(Some(script));
    let _uninstall = Uninstall;
    let built = build();
    let script = HELLO_SCRIPT.take().expect("script installed above");
    (built, script)
}

/// The X25519MLKEM768 group, offering the scripted key share while a hello is
/// being built.
#[derive(Debug)]
struct HybridGroup;

impl SupportedKxGroup for HybridGroup {
    fn start(&self) -> std::result::Result<Box<dyn ActiveKeyExchange>, TlsError> {
        let scripted = HELLO_SCRIPT
            .with_borrow(|script| script.as_ref().map(|script| script.key_share.clone()));
        // rustls has no reason to come back for another share once the hello
        // is out; a fresh one keeps the group well-formed if it ever does.
        Ok(Box::new(scripted.unwrap_or_else(HybridKeyShare::generate)))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// The ring provider's random source, recorded or replayed while a hello is
/// being built.
#[derive(Debug)]
struct ScriptedRandom;

impl SecureRandom for ScriptedRandom {
    fn fill(&self, buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
        fn fresh(buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
            use ring::rand::SecureRandom as _;
            ring::rand::SystemRandom::new()
                .fill(buf)
                .map_err(|_| GetRandomFailed)
        }

        HELLO_SCRIPT.with_borrow_mut(|script| match script {
            None => fresh(buf),
            Some(HelloScript {
                random,
                replay: None,
                ..
            }) => {
                fresh(buf)?;
                random.extend_from_slice(buf);
                Ok(())
            }
            Some(HelloScript {
                random,
                replay: Some(at),
                ..
            }) => {
                let end = *at + buf.len();
                buf.copy_from_slice(random.get(*at..end).ok_or(GetRandomFailed)?);
                *at = end;
                Ok(())
            }
        })
    }
}

const TLS_RECORD_HEADER_LEN: usize = 5;
/// Where a ClientHello handshake message keeps its random and session ID:
/// type (1), length (3), legacy_version (2), random (32), session ID length
/// (1), session ID (32).
const HELLO_RANDOM: Range<usize> = 6..38;
const HELLO_SESSION_ID_LENGTH: usize = 38;
const HELLO_SESSION_ID: Range<usize> = 39..71;

/// Start a REALITY handshake whose ClientHello offers X25519MLKEM768 ahead of
/// X25519.
///
/// Deliberately not `async`: nothing may suspend between `build_scripted`
/// installing the thread-local script and rustls reading it.
fn connect_hybrid<S>(
    stream: S,
    config: &RealityConfig,
    server_name: ServerName<'static>,
) -> Result<tokio_rustls::Connect<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key_share = HybridKeyShare::generate();
    // mihomo compat: reality.go runs the auth ECDH with the plain X25519
    // share's key (`KeyShareKeys.Ecdhe`), and the server reads that same
    // share. Here it is also the X25519 half of the hybrid share.
    let shared_secret = key_share
        .x25519(&config.public_key)
        .map_err(|_| anyhow::anyhow!("REALITY: unusable public key"))?;

    let auth_key = AuthKeySlot::default();
    let tls_config = Arc::new(client_config(config, Some(&auth_key))?);

    // First build: a throwaway connection, wanted only for the hello it queues.
    let script = HelloScript {
        key_share,
        random: Vec::new(),
        replay: None,
    };
    let (probe, mut script) = build_scripted(script, || {
        rustls::ClientConnection::new(tls_config.clone(), server_name.clone())
    });
    let mut probe = probe.context("REALITY: building the ClientHello failed")?;
    let mut record = Vec::new();
    while probe.wants_write() {
        probe.write_tls(&mut record)?;
    }
    let hello = record
        .get_mut(TLS_RECORD_HEADER_LEN..)
        .filter(|hello| {
            hello.len() >= HELLO_SESSION_ID.end
                && hello[0] == 0x01
                && hello[HELLO_SESSION_ID_LENGTH] == 32
        })
        .context("REALITY: rustls produced an unexpected ClientHello")?;

    let drawn_session_id = hello[HELLO_SESSION_ID].to_vec();
    let key = seal_session_id(hello, shared_secret.as_bytes(), &config.short_id)
        .map_err(|_| anyhow::anyhow!("REALITY: sealing the session ID failed"))?;
    *auth_key.lock().unwrap_or_else(PoisonError::into_inner) = Some(key);

    // Second build: the real connection, replaying the first one's randomness
    // with the sealed session ID where the drawn one was.
    let drawn_at = script
        .random
        .windows(drawn_session_id.len())
        .position(|window| window == drawn_session_id)
        .context("REALITY: rustls did not draw the session ID from its random source")?;
    script.random[drawn_at..drawn_at + drawn_session_id.len()]
        .copy_from_slice(&hello[HELLO_SESSION_ID]);
    script.replay = Some(0);
    let (connect, script) = build_scripted(script, || {
        tokio_rustls::TlsConnector::from(tls_config).connect(server_name, stream)
    });
    if script.replay != Some(script.random.len()) {
        anyhow::bail!("REALITY: rustls did not rebuild the same ClientHello");
    }
    Ok(connect)
}

/// Seal the REALITY auth into the session ID of `hello`, a ClientHello
/// handshake message, and return the auth key the server proves it shares by
/// signing its certificate with it.
///
/// mihomo compat: `GetRealityConn` (component/tls/reality.go).
fn seal_session_id(
    hello: &mut [u8],
    shared_secret: &[u8],
    short_id: &[u8; MAX_SHORT_ID_LEN],
) -> std::result::Result<[u8; 32], ring::error::Unspecified> {
    // The hello is the AEAD's associated data, with its session ID zeroed.
    hello[HELLO_SESSION_ID].fill(0);
    let random = &hello[HELLO_RANDOM];

    let mut auth_key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20])
        .extract(shared_secret)
        .expand(&[b"REALITY"], hkdf::HKDF_SHA256)?
        .fill(&mut auth_key)?;

    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut session_id = [0u8; 32];
    session_id[..8].copy_from_slice(&unix_time.to_be_bytes());
    session_id[..3].copy_from_slice(&MIHOMO_REALITY_VERSION);
    session_id[8..16].copy_from_slice(short_id);

    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &auth_key)?);
    let nonce = aead::Nonce::try_assume_unique_for_key(&random[20..])?;
    let (plaintext, tag) = session_id.split_at_mut(16);
    tag.copy_from_slice(
        key.seal_in_place_separate_tag(nonce, aead::Aad::from(&*hello), plaintext)?
            .as_ref(),
    );

    hello[HELLO_SESSION_ID].copy_from_slice(&session_id);
    Ok(auth_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::KeyPair as _;
    use sha2::Sha256;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use x25519_dalek::{PublicKey, StaticSecret};

    const X25519: u16 = 0x001d;
    const X25519MLKEM768: u16 = 0x11ec;

    fn encoded_key(bytes: [u8; 32]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn config(public_key: [u8; 32], short_id: &str, support_x25519mlkem768: bool) -> RealityConfig {
        RealityConfig::from_opts(
            &encoded_key(public_key),
            short_id,
            "example.com".to_string(),
            TlsFingerprint::Chrome,
            vec!["h2".to_string(), "http/1.1".to_string()],
            support_x25519mlkem768,
        )
        .unwrap()
    }

    #[test]
    fn parses_raw_urlsafe_public_key_and_pads_short_id() {
        let parsed = config([0xff; 32], "a1b2c3", false);
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
    fn validates_short_id() {
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
    }

    #[test]
    fn hybrid_key_share_needs_the_flag_and_a_fingerprint_that_has_one() {
        let offers_hybrid = |fingerprint, support_x25519mlkem768| {
            RealityConfig::from_opts(
                &encoded_key([1; 32]),
                "",
                "example.com".to_string(),
                fingerprint,
                vec![],
                support_x25519mlkem768,
            )
            .unwrap()
            .x25519mlkem768
        };
        assert!(offers_hybrid(TlsFingerprint::Chrome, true));
        assert!(!offers_hybrid(TlsFingerprint::Chrome, false));
        // mihomo compat: HelloIOS_14 has no hybrid share for the flag to keep.
        assert!(!offers_hybrid(TlsFingerprint::Ios, true));
    }

    /// Read one TLS record, header included.
    async fn read_record(io: &mut DuplexStream) -> Vec<u8> {
        let mut record = vec![0u8; TLS_RECORD_HEADER_LEN];
        io.read_exact(&mut record).await.unwrap();
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        record.resize(TLS_RECORD_HEADER_LEN + len, 0);
        io.read_exact(&mut record[TLS_RECORD_HEADER_LEN..])
            .await
            .unwrap();
        record
    }

    /// Read the ClientHello handshake message `wrap_reality` opens with.
    async fn read_client_hello(io: &mut DuplexStream) -> Vec<u8> {
        let record = read_record(io).await;
        assert_eq!(record[0], 0x16);
        let hello = record[TLS_RECORD_HEADER_LEN..].to_vec();
        assert_eq!(hello[0], 0x01);
        assert_eq!(hello[HELLO_SESSION_ID_LENGTH], 32);
        hello
    }

    /// `(type, body)` of every extension in a ClientHello, in wire order.
    fn extensions(hello: &[u8]) -> Vec<(u16, &[u8])> {
        let u16_at = |at: usize| u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
        let mut offset = HELLO_SESSION_ID.end;
        offset += 2 + u16_at(offset); // cipher suites
        offset += 1 + hello[offset] as usize; // compression methods
        let end = offset + 2 + u16_at(offset);
        offset += 2;

        let mut extensions = Vec::new();
        while offset < end {
            let body = offset + 4..offset + 4 + u16_at(offset + 2);
            extensions.push((u16_at(offset) as u16, &hello[body.clone()]));
            offset = body.end;
        }
        extensions
    }

    fn extension(hello: &[u8], extension_type: u16) -> &[u8] {
        extensions(hello)
            .into_iter()
            .find(|(found, _)| *found == extension_type)
            .map(|(_, body)| body)
            .unwrap()
    }

    /// `(group, key)` of every key share a ClientHello offers, in wire order.
    fn key_shares(hello: &[u8]) -> Vec<(u16, &[u8])> {
        let mut entries = &extension(hello, 0x0033)[2..];
        let mut shares = Vec::new();
        while !entries.is_empty() {
            let group = u16::from_be_bytes([entries[0], entries[1]]);
            let len = u16::from_be_bytes([entries[2], entries[3]]) as usize;
            shares.push((group, &entries[4..4 + len]));
            entries = &entries[4 + len..];
        }
        shares
    }

    /// Authenticate a ClientHello the way a REALITY server does — with the
    /// plain X25519 share — and return the auth key it derives.
    fn authenticate(hello: &[u8], server_secret: &StaticSecret, short_id: [u8; 8]) -> [u8; 32] {
        let client_public: [u8; 32] = key_shares(hello)
            .into_iter()
            .find(|(group, _)| *group == X25519)
            .unwrap()
            .1
            .try_into()
            .unwrap();
        let shared_secret = server_secret
            .diffie_hellman(&PublicKey::from(client_public))
            .to_bytes();
        let random = &hello[HELLO_RANDOM];
        let mut auth_key = [0u8; 32];
        ::hkdf::Hkdf::<Sha256>::new(Some(&random[..20]), &shared_secret)
            .expand(b"REALITY", &mut auth_key)
            .unwrap();

        let mut aad = hello.to_vec();
        aad[HELLO_SESSION_ID].fill(0);
        let plaintext = Aes256Gcm::new_from_slice(&auth_key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&random[20..]),
                Payload {
                    msg: &hello[HELLO_SESSION_ID],
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
        assert_eq!(&plaintext[8..], &short_id);
        auth_key
    }

    #[tokio::test]
    async fn client_hello_contains_mihomo_reality_session_id() {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "01020304", false);
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let client = tokio::spawn(async move { wrap_reality(client_io, &config).await });

        let hello = read_client_hello(&mut server_io).await;
        let shares = key_shares(&hello);
        assert_eq!(shares.len(), 1);
        assert_eq!((shares[0].0, shares[0].1.len()), (X25519, 32));
        authenticate(&hello, &server_secret, [1, 2, 3, 4, 0, 0, 0, 0]);

        drop(server_io);
        assert!(client.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn hybrid_client_hello_offers_x25519mlkem768_then_x25519() {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "fb", true);
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let client = tokio::spawn(async move { wrap_reality(client_io, &config).await });

        let hello = read_client_hello(&mut server_io).await;
        // What XTLS/REALITY demands since 8cdf7bf: the hybrid share, then X25519.
        let shares = key_shares(&hello);
        assert_eq!(shares.len(), 2);
        assert_eq!(
            (shares[0].0, shares[0].1.len()),
            (X25519MLKEM768, 1184 + 32)
        );
        assert_eq!((shares[1].0, shares[1].1), (X25519, &shares[0].1[1184..]));
        // supported_groups leads with the hybrid group too.
        assert_eq!(
            &extension(&hello, 0x000a)[2..4],
            &X25519MLKEM768.to_be_bytes()
        );
        // The hello is still a complete one: ALPN survives the double build.
        assert_eq!(
            extension(&hello, 0x0010),
            b"\x00\x0c\x02h2\x08http/1.1".as_slice()
        );
        // The session ID was sealed over exactly the bytes that went out.
        authenticate(&hello, &server_secret, [0xfb, 0, 0, 0, 0, 0, 0, 0]);

        drop(server_io);
        assert!(client.await.unwrap().is_err());
    }

    /// Finish TLS 1.3 the way a REALITY server does: with an Ed25519
    /// certificate whose signature field is HMAC-SHA512(`auth_key`, public
    /// key). `record` is the ClientHello record already read off `io`.
    async fn accept_tls(
        io: DuplexStream,
        record: Vec<u8>,
        auth_key: [u8; 32],
    ) -> std::io::Result<tokio_rustls::server::TlsStream<impl AsyncRead + AsyncWrite + Unpin>> {
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let public_key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = public_key.public_key().as_ref();
        // Just the SubjectPublicKeyInfo and the trailing 64-byte signature: the
        // two parts of the certificate a REALITY client looks at.
        let mut certificate = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".to_vec();
        certificate.extend_from_slice(public_key);
        let mac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &auth_key);
        certificate.extend_from_slice(ring::hmac::sign(&mac_key, public_key).as_ref());

        let signing_key =
            rustls::crypto::ring::sign::any_eddsa_type(&pkcs8.as_ref().to_vec().into()).unwrap();
        let certified = rustls::sign::CertifiedKey::new(vec![certificate.into()], signing_key);
        // X25519 only, so the client has to finish on the X25519 half of its
        // hybrid share.
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));

        let (read, write) = tokio::io::split(io);
        let io = tokio::io::join(std::io::Cursor::new(record).chain(read), write);
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(io)
            .await
    }

    #[tokio::test]
    async fn hybrid_handshake_authenticates_the_server() {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "fb", true);
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);

        let server = tokio::spawn(async move {
            let record = read_record(&mut server_io).await;
            let auth_key = authenticate(
                &record[TLS_RECORD_HEADER_LEN..],
                &server_secret,
                [0xfb, 0, 0, 0, 0, 0, 0, 0],
            );
            let mut stream = accept_tls(server_io, record, auth_key).await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
            ping
        });

        let mut stream = wrap_reality(client_io, &config).await.unwrap();
        assert_eq!(
            stream
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .unwrap()
                .name(),
            NamedGroup::X25519
        );
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&server.await.unwrap(), b"ping");
        assert_eq!(&pong, b"pong");
    }

    #[tokio::test]
    async fn hybrid_handshake_rejects_a_certificate_signed_with_another_key() {
        let server_public = PublicKey::from(&StaticSecret::from([0x42; 32])).to_bytes();
        let config = config(server_public, "fb", true);
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);

        // What a server without the private key is reduced to: it cannot
        // derive the session's auth key, so it signs with some other one.
        let server = tokio::spawn(async move {
            let record = read_record(&mut server_io).await;
            accept_tls(server_io, record, [0x24; 32]).await.is_err()
        });

        assert!(wrap_reality(client_io, &config).await.is_err());
        assert!(server.await.unwrap());
    }
}
