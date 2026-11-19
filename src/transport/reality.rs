//! Mihomo-compatible REALITY client transport.
//!
//! REALITY authentication is carried inside the TLS 1.3 ClientHello session
//! ID. It is not an application-data header and has no acknowledgement byte:
//! the server answers by presenting a certificate only the holder of the
//! configured private key could have produced.
//!
//! mihomo builds that ClientHello with uTLS from a browser preset and runs
//! the handshake on uTLS's fork of Go's `crypto/tls`. The same three pieces
//! live here: [`hello`] builds the preset hello, this module seals REALITY's
//! session ID into it, and [`tls13`] is the TLS 1.3 client that takes it from
//! there. A server that turns out not to be REALITY's gets [`fallback`].

mod cert;
mod fallback;
mod hello;
mod tls13;

use anyhow::{anyhow, bail, Result};
use base64::Engine as _;
use ring::{aead, hkdf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use super::x25519mlkem768;
pub use hello::Preset;
pub use tls13::RealityStream;

/// REALITY protocol version sent by current mihomo Meta.
const MIHOMO_REALITY_VERSION: [u8; 3] = [1, 8, 2];
/// mihomo `RealityMaxShortIDLen`.
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
    /// The uTLS preset `client-fingerprint` selects, if it names one.
    pub preset: Option<Preset>,
    /// `support-x25519mlkem768`: keep the preset's X25519MLKEM768 key share.
    pub x25519mlkem768: bool,
}

impl RealityConfig {
    /// Parse mihomo `reality-opts` without retaining encoded config strings.
    ///
    /// mihomo compat: `RealityOptions.Parse` (`adapter/outbound/reality.go`),
    /// error texts included.
    pub fn from_opts(
        public_key_b64: &str,
        short_id_hex: &str,
        server_name: String,
        client_fingerprint: Option<&str>,
        support_x25519mlkem768: bool,
    ) -> Result<Self> {
        // base64.RawURLEncoding: URL-safe alphabet, no padding.
        let public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key_b64)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow!("invalid REALITY public key"))?;

        if short_id_hex.len() / 2 > MAX_SHORT_ID_LEN {
            bail!("invalid REALITY short id");
        }
        let decoded = hex::decode(short_id_hex).map_err(|_| anyhow!("invalid REALITY short ID"))?;
        let mut short_id = [0u8; MAX_SHORT_ID_LEN];
        short_id[..decoded.len()].copy_from_slice(&decoded);

        Ok(Self {
            public_key,
            short_id,
            server_name,
            preset: Preset::from_name(client_fingerprint),
            x25519mlkem768: support_x25519mlkem768,
        })
    }
}

/// Establish a REALITY-authenticated TLS 1.3 stream.
///
/// mihomo compat: `GetRealityConn` (`component/tls/reality.go`).
pub async fn wrap_reality<S>(stream: S, config: &RealityConfig) -> Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // mihomo compat: `StreamTLSConn` (`transport/vmess/tls.go`).
    let preset = config
        .preset
        .ok_or_else(|| anyhow!("REALITY is based on uTLS, please set a client-fingerprint"))?;
    let mut hello = hello::build(preset, &config.server_name, config.x25519mlkem768)?;

    // The auth ECDH uses the plain X25519 share's key, and the hybrid share's
    // X25519 half only when the hello has no plain share — the same order the
    // server looks for them in.
    let ecdhe = hello
        .keys
        .ecdhe
        .as_ref()
        .or_else(|| {
            hello
                .keys
                .hybrid
                .as_ref()
                .map(|hybrid| hybrid.x25519_secret())
        })
        .ok_or_else(|| anyhow!("nil ecdheKey"))?;
    let shared_secret = x25519mlkem768::x25519(ecdhe, &config.public_key)
        .map_err(|_| anyhow!("crypto/ecdh: bad X25519 remote ECDH input"))?;
    let now = crate::ntp::now();
    let auth_key = seal_session_id(&mut hello.raw, &shared_secret, &config.short_id, now)
        .map_err(|_| anyhow!("REALITY: sealing the session ID failed"))?;

    let established = tls13::connect(
        stream,
        hello,
        tls13::Verify {
            auth_key: &auth_key,
            server_name: &config.server_name,
            now,
        },
    )
    .await?;
    debug!(
        "REALITY is using X25519MLKEM768 for TLS' communication: {}",
        established.group == hello::X25519MLKEM768
    );
    let verified = established.peer == cert::Peer::Reality;
    debug!("REALITY Authentication: {verified}");

    if !verified {
        // The other end has a valid certificate for the camouflage name: it
        // is the real site, or a server that would not authenticate us.
        // Finish like the browser the hello claimed to be.
        tokio::spawn(fallback::browse(
            established.stream,
            config.server_name.clone(),
            preset.client(),
        ));
        bail!("REALITY authentication failed");
    }
    Ok(established.stream)
}

/// Seal the REALITY auth into the session ID of `hello`, a ClientHello
/// handshake message, and return the auth key the server proves it shares by
/// signing its certificate with it.
///
/// mihomo compat: `GetRealityConn` (`component/tls/reality.go`).
fn seal_session_id(
    hello: &mut [u8],
    shared_secret: &[u8],
    short_id: &[u8; MAX_SHORT_ID_LEN],
    now: SystemTime,
) -> std::result::Result<[u8; 32], ring::error::Unspecified> {
    // The hello is the AEAD's associated data, with its session ID zeroed.
    hello[hello::SESSION_ID].fill(0);
    let random = &hello[hello::RANDOM];

    let mut auth_key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20])
        .extract(shared_secret)
        .expand(&[b"REALITY"], hkdf::HKDF_SHA256)?
        .fill(&mut auth_key)?;

    let unix_time = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
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

    hello[hello::SESSION_ID].copy_from_slice(&session_id);
    Ok(auth_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hello::tests::{extension, key_shares};
    use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
    use rustls::{NamedGroup, SupportedCipherSuite};
    use sha2::Sha256;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use x25519_dalek::{PublicKey, StaticSecret};

    const X25519: u16 = 0x001d;
    const X25519MLKEM768: u16 = 0x11ec;
    const TLS_RECORD_HEADER_LEN: usize = 5;

    fn encoded_key(bytes: [u8; 32]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn config(public_key: [u8; 32], short_id: &str, support_x25519mlkem768: bool) -> RealityConfig {
        RealityConfig::from_opts(
            &encoded_key(public_key),
            short_id,
            "example.com".to_string(),
            Some("chrome"),
            support_x25519mlkem768,
        )
        .unwrap()
    }

    fn from_opts_error(public_key: &str, short_id: &str) -> String {
        RealityConfig::from_opts(
            public_key,
            short_id,
            "example.com".to_string(),
            Some("chrome"),
            false,
        )
        .unwrap_err()
        .to_string()
    }

    #[test]
    fn parses_raw_urlsafe_public_key_and_pads_short_id() {
        let parsed = config([0xff; 32], "a1b2c3", false);
        assert_eq!(parsed.public_key, [0xff; 32]);
        assert_eq!(parsed.short_id, [0xa1, 0xb2, 0xc3, 0, 0, 0, 0, 0]);
        assert_eq!(parsed.preset, Some(Preset::Chrome133));
        // An absent short ID is eight zero bytes.
        assert_eq!(config([1; 32], "", false).short_id, [0; 8]);
    }

    #[test]
    fn rejects_keys_mihomo_rejects() {
        // adapter/outbound/reality.go: base64.RawURLEncoding, exactly 32 bytes.
        let padded = format!("{}=", encoded_key([0xff; 32]));
        let standard = base64::engine::general_purpose::STANDARD.encode([0xff; 32]);
        let short = URL_SAFE_NO_PAD.encode([0xff; 31]);
        for key in [padded.as_str(), standard.as_str(), short.as_str(), "", " "] {
            assert_eq!(from_opts_error(key, ""), "invalid REALITY public key");
        }
    }

    #[test]
    fn rejects_short_ids_mihomo_rejects() {
        let key = encoded_key([1; 32]);
        assert_eq!(
            from_opts_error(&key, "001122334455667788"),
            "invalid REALITY short id"
        );
        for short_id in ["not-hex", "abc", "0g"] {
            assert_eq!(from_opts_error(&key, short_id), "invalid REALITY short ID");
        }
        assert!(RealityConfig::from_opts(
            &key,
            "0011223344556677",
            "example.com".to_string(),
            None,
            false
        )
        .is_ok());
    }

    #[tokio::test]
    async fn a_client_fingerprint_is_required() {
        // transport/vmess/tls.go StreamTLSConn.
        for fingerprint in [None, Some(""), Some("none"), Some("no-such-browser")] {
            let config = RealityConfig::from_opts(
                &encoded_key([1; 32]),
                "",
                "example.com".to_string(),
                fingerprint,
                true,
            )
            .unwrap();
            let (client_io, _server_io) = tokio::io::duplex(4096);
            let error = wrap_reality(client_io, &config).await.err().unwrap();
            assert_eq!(
                error.to_string(),
                "REALITY is based on uTLS, please set a client-fingerprint"
            );
        }
        // A TLS 1.2-only preset has no key share to authenticate with.
        let config = RealityConfig::from_opts(
            &encoded_key([1; 32]),
            "",
            "example.com".to_string(),
            Some("android"),
            true,
        )
        .unwrap();
        let (client_io, _server_io) = tokio::io::duplex(4096);
        let error = wrap_reality(client_io, &config).await.err().unwrap();
        assert_eq!(error.to_string(), "nil ecdheKey");
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
        // Go sends the first ClientHello in a TLS 1.0 record.
        assert_eq!(record[..3], [0x16, 0x03, 0x01]);
        let hello = record[TLS_RECORD_HEADER_LEN..].to_vec();
        assert_eq!(hello[0], 0x01);
        assert_eq!(hello[38], 32);
        hello
    }

    /// Authenticate a ClientHello the way a REALITY server does — with the
    /// plain X25519 share when there is one, else the hybrid share's X25519
    /// half — and return the auth key it derives.
    fn authenticate(hello: &[u8], server_secret: &StaticSecret, short_id: [u8; 8]) -> [u8; 32] {
        let shares = key_shares(hello);
        let client_public: [u8; 32] = shares
            .iter()
            .find(|(group, _)| *group == X25519)
            .map(|(_, key)| *key)
            .or_else(|| {
                shares
                    .iter()
                    .find(|(group, _)| *group == X25519MLKEM768)
                    .map(|(_, key)| &key[1184..])
            })
            .unwrap()
            .try_into()
            .unwrap();
        let shared_secret = server_secret
            .diffie_hellman(&PublicKey::from(client_public))
            .to_bytes();
        let random = &hello[hello::RANDOM];
        let mut auth_key = [0u8; 32];
        ::hkdf::Hkdf::<Sha256>::new(Some(&random[..20]), &shared_secret)
            .expand(b"REALITY", &mut auth_key)
            .unwrap();

        let mut aad = hello.to_vec();
        aad[hello::SESSION_ID].fill(0);
        let plaintext = Aes256Gcm::new_from_slice(&auth_key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&random[20..]),
                Payload {
                    msg: &hello[hello::SESSION_ID],
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
        let (client_io, mut server_io) = tokio::io::duplex(8192);

        let client = tokio::spawn(async move { wrap_reality(client_io, &config).await });

        let hello = read_client_hello(&mut server_io).await;
        // Without `support-x25519mlkem768` the hybrid share is stripped.
        let shares = key_shares(&hello);
        assert_eq!(shares.len(), 2);
        assert_eq!((shares[1].0, shares[1].1.len()), (X25519, 32));
        authenticate(&hello, &server_secret, [1, 2, 3, 4, 0, 0, 0, 0]);

        drop(server_io);
        assert!(client.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn hybrid_client_hello_offers_x25519mlkem768_then_x25519() {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "fb", true);
        let (client_io, mut server_io) = tokio::io::duplex(8192);

        let client = tokio::spawn(async move { wrap_reality(client_io, &config).await });

        let hello = read_client_hello(&mut server_io).await;
        // What XTLS/REALITY demands since 8cdf7bf: the hybrid share, then X25519.
        let shares: Vec<_> = key_shares(&hello)
            .into_iter()
            .filter(|(group, _)| [X25519, X25519MLKEM768].contains(group))
            .collect();
        assert_eq!(shares.len(), 2);
        assert_eq!(
            (shares[0].0, shares[0].1.len()),
            (X25519MLKEM768, 1184 + 32)
        );
        assert_eq!((shares[1].0, shares[1].1.len()), (X25519, 32));
        // The preset's ALPN, whatever the transport: mihomo never overrides it.
        assert_eq!(
            extension(&hello, 0x0010).unwrap(),
            b"\x00\x0c\x02h2\x08http/1.1".as_slice()
        );
        // The session ID was sealed over exactly the bytes that went out, and
        // with the plain X25519 share's key.
        authenticate(&hello, &server_secret, [0xfb, 0, 0, 0, 0, 0, 0, 0]);

        drop(server_io);
        assert!(client.await.unwrap().is_err());
    }

    /// X25519MLKEM768 for the rustls test server, which the ring provider
    /// lacks: encapsulate to the client's ML-KEM key, X25519 against the rest.
    #[derive(Debug)]
    struct ServerHybridGroup;

    impl SupportedKxGroup for ServerHybridGroup {
        fn start(&self) -> std::result::Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
            Err(rustls::Error::General("server side only".into()))
        }

        fn start_and_complete(
            &self,
            client_share: &[u8],
        ) -> std::result::Result<CompletedKeyExchange, rustls::Error> {
            let (encapsulation_key, x25519) = client_share.split_at(1184);
            let (pub_key, secret) = x25519mlkem768::tests::server_side(encapsulation_key, x25519);
            Ok(CompletedKeyExchange {
                group: self.name(),
                pub_key,
                secret: SharedSecret::from(secret),
            })
        }

        fn name(&self) -> NamedGroup {
            NamedGroup::X25519MLKEM768
        }
    }

    /// A REALITY server signs its CertificateVerify with Ed25519 whether or
    /// not the ClientHello offered it — no browser preset does.
    #[derive(Debug)]
    struct AlwaysEd25519(Arc<dyn rustls::sign::SigningKey>);

    impl rustls::sign::SigningKey for AlwaysEd25519 {
        fn choose_scheme(
            &self,
            _offered: &[rustls::SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            self.0.choose_scheme(&[rustls::SignatureScheme::ED25519])
        }

        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.0.algorithm()
        }
    }

    /// Finish TLS 1.3 the way a REALITY server does: with an Ed25519
    /// certificate whose signature field is HMAC-SHA512(`auth_key`, public
    /// key). `record` is the ClientHello record already read off `io`.
    async fn accept_tls(
        io: DuplexStream,
        record: Vec<u8>,
        auth_key: [u8; 32],
        suite: SupportedCipherSuite,
        hybrid: bool,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<impl AsyncRead + AsyncWrite + Unpin>> {
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = ring::signature::KeyPair::public_key(&key_pair).as_ref();
        let mac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &auth_key);
        let certificate = cert::tests::ed25519_certificate(
            public_key,
            ring::hmac::sign(&mac_key, public_key).as_ref(),
        );

        let signing_key =
            rustls::crypto::ring::sign::any_eddsa_type(&pkcs8.as_ref().to_vec().into()).unwrap();
        let certified = rustls::sign::CertifiedKey::new(
            vec![certificate.into()],
            Arc::new(AlwaysEd25519(signing_key)),
        );
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites = vec![suite];
        provider.kx_groups = if hybrid {
            vec![&ServerHybridGroup]
        } else {
            vec![rustls::crypto::ring::kx_group::X25519]
        };
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

    /// A REALITY handshake against a rustls server, then data both ways:
    /// enough from the client to walk through every early record size, and
    /// enough from the server to span many records.
    async fn handshake_and_relay(suite: SupportedCipherSuite, hybrid: bool) {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "fb", hybrid);
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let upload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let download: Vec<u8> = (0..300_000u32).map(|i| (i % 241) as u8).collect();
        let (expected_upload, to_download) = (upload.clone(), download.clone());

        let server = tokio::spawn(async move {
            let record = read_record(&mut server_io).await;
            let auth_key = authenticate(
                &record[TLS_RECORD_HEADER_LEN..],
                &server_secret,
                [0xfb, 0, 0, 0, 0, 0, 0, 0],
            );
            let mut stream = accept_tls(server_io, record, auth_key, suite, hybrid)
                .await
                .unwrap();
            let mut received = vec![0u8; expected_upload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_upload);
            stream.write_all(&to_download).await.unwrap();
            stream.shutdown().await.unwrap();
            // The client's close_notify ends the stream cleanly.
            assert_eq!(stream.read(&mut [0u8; 1]).await.unwrap(), 0);
        });

        let mut stream = wrap_reality(client_io, &config).await.unwrap();
        stream.write_all(&upload).await.unwrap();
        stream.flush().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, download);
        stream.shutdown().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_authenticates_and_relays_on_every_suite() {
        use rustls::crypto::ring::cipher_suite::{
            TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
        };
        for suite in [
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
            TLS13_CHACHA20_POLY1305_SHA256,
        ] {
            handshake_and_relay(suite, false).await;
        }
    }

    #[tokio::test]
    async fn hybrid_handshake_authenticates_and_relays() {
        handshake_and_relay(
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_a_certificate_signed_with_another_key() {
        let server_public = PublicKey::from(&StaticSecret::from([0x42; 32])).to_bytes();
        let config = config(server_public, "fb", true);
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);

        // What a server without the private key is reduced to: it cannot
        // derive the session's auth key, so it signs with some other one.
        let server = tokio::spawn(async move {
            let record = read_record(&mut server_io).await;
            accept_tls(
                server_io,
                record,
                [0x24; 32],
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
                false,
            )
            .await
            .err()
            .map(|error| error.to_string())
        });

        let error = wrap_reality(client_io, &config).await.err().unwrap();
        assert!(error.to_string().starts_with("x509: "), "{error}");
        // The server could read the client's alert: it left protected by the
        // handshake keys, behind the ChangeCipherSpec, as Go sends it.
        let alert = server.await.unwrap().unwrap();
        assert!(alert.contains("BadCertificate"), "{alert}");
    }

    #[tokio::test]
    async fn follows_a_server_key_update() {
        let server_secret = StaticSecret::from([0x42; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let config = config(server_public, "", false);
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let record = read_record(&mut server_io).await;
            let auth_key = authenticate(&record[TLS_RECORD_HEADER_LEN..], &server_secret, [0; 8]);
            let mut stream = accept_tls(
                server_io,
                record,
                auth_key,
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
                false,
            )
            .await
            .unwrap();
            stream.write_all(b"before").await.unwrap();
            // A KeyUpdate that asks the client to update too.
            stream.get_mut().1.refresh_traffic_keys().unwrap();
            stream.write_all(b"after").await.unwrap();
            stream.flush().await.unwrap();
            // The client's answer and its next data arrive under new keys.
            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).await.unwrap();
            reply
        });

        let mut stream = wrap_reality(client_io, &config).await.unwrap();
        let mut received = [0u8; 11];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"beforeafter");
        stream.write_all(b"pong").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(&server.await.unwrap(), b"pong");
    }
}
