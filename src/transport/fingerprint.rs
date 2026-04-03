//! TLS ClientHello fingerprinting.
//!
//! GFW and other DPI systems classify TLS connections by the cipher suite
//! order, supported groups, and extension layout in the ClientHello.  A
//! vanilla rustls handshake is trivially distinguishable from browser traffic.
//!
//! This module provides [`TlsFingerprint`] variants that reorder the
//! `CryptoProvider` cipher suites and key-exchange groups to match the
//! real ClientHello of popular browsers, making the connection appear as
//! legitimate browser traffic to passive observers.

use rustls::crypto::ring as ring_provider;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::SupportedCipherSuite;
use std::fmt;

// Re-export cipher suites from the ring provider for convenient access.
use ring_provider::cipher_suite::*;
use ring_provider::kx_group;

/// A TLS ClientHello fingerprint that mimics a specific browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsFingerprint {
    /// Google Chrome / Chromium fingerprint.
    Chrome,
    /// Mozilla Firefox fingerprint.
    Firefox,
    /// Apple Safari fingerprint.
    Safari,
    /// iOS Safari fingerprint.
    Ios,
    /// Android Chrome fingerprint.
    Android,
    /// Randomised cipher suite order (each connection differs).
    Random,
    /// No fingerprint manipulation — use rustls defaults.
    #[default]
    None,
}

impl TlsFingerprint {
    /// Parse a fingerprint name from configuration strings.
    ///
    /// Accepts common aliases used by Clash/Mihomo/Sing-box configs.
    pub fn from_str_opt(s: Option<&str>) -> Self {
        match s {
            Some(s) => match s.to_lowercase().as_str() {
                "chrome" => Self::Chrome,
                "firefox" => Self::Firefox,
                "safari" => Self::Safari,
                "ios" => Self::Ios,
                "android" => Self::Android,
                "random" | "randomized" => Self::Random,
                "none" | "" => Self::None,
                _ => Self::None,
            },
            None => Self::None,
        }
    }
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chrome => write!(f, "chrome"),
            Self::Firefox => write!(f, "firefox"),
            Self::Safari => write!(f, "safari"),
            Self::Ios => write!(f, "ios"),
            Self::Android => write!(f, "android"),
            Self::Random => write!(f, "random"),
            Self::None => write!(f, "none"),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-browser cipher suite and key-exchange group orderings
// ---------------------------------------------------------------------------

/// Chrome 120+ cipher suite order.
///
/// Chrome sends TLS 1.3 suites first (AES-128-GCM preferred over AES-256-GCM,
/// then CHACHA20), followed by TLS 1.2 ECDHE suites with ECDSA before RSA.
fn chrome_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        // TLS 1.3
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        // TLS 1.2
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// Chrome key-exchange group order: X25519 first, then P-256, P-384.
fn chrome_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1]
}

/// Firefox 121+ cipher suite order.
///
/// Firefox puts AES-128-GCM first in TLS 1.3, CHACHA20 second, then AES-256,
/// followed by the TLS 1.2 suites with ECDSA variants before RSA.
fn firefox_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        // TLS 1.3
        TLS13_AES_128_GCM_SHA256,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS13_AES_256_GCM_SHA384,
        // TLS 1.2
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ]
}

/// Firefox key-exchange group order: X25519, P-256, P-384.
fn firefox_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1]
}

/// Safari (macOS / iOS) cipher suite order.
///
/// Safari prefers CHACHA20 over AES in TLS 1.3 and lists ECDSA suites before
/// RSA in TLS 1.2.
fn safari_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        // TLS 1.3
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        // TLS 1.2
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// Safari key-exchange group order: P-256 first (Apple preference), then
/// X25519, P-384.
fn safari_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![kx_group::SECP256R1, kx_group::X25519, kx_group::SECP384R1]
}

/// iOS Safari — same as desktop Safari.
fn ios_cipher_suites() -> Vec<SupportedCipherSuite> {
    safari_cipher_suites()
}

fn ios_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    safari_kx_groups()
}

/// Android Chrome — same order as desktop Chrome.
fn android_cipher_suites() -> Vec<SupportedCipherSuite> {
    chrome_cipher_suites()
}

fn android_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    chrome_kx_groups()
}

/// Randomised order — Fisher-Yates shuffle the available suites.
fn random_cipher_suites() -> Vec<SupportedCipherSuite> {
    use rand::seq::SliceRandom;
    let mut suites = ring_provider::ALL_CIPHER_SUITES.to_vec();
    let mut rng = rand::thread_rng();
    suites.shuffle(&mut rng);
    suites
}

fn random_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    use rand::seq::SliceRandom;
    let mut groups = ring_provider::ALL_KX_GROUPS.to_vec();
    let mut rng = rand::thread_rng();
    groups.shuffle(&mut rng);
    groups
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a [`CryptoProvider`] with cipher suites and key-exchange groups
/// ordered to match the given fingerprint.
pub fn make_crypto_provider(fingerprint: TlsFingerprint) -> CryptoProvider {
    let base = ring_provider::default_provider();

    let (cipher_suites, kx_groups) = match fingerprint {
        TlsFingerprint::Chrome => (chrome_cipher_suites(), chrome_kx_groups()),
        TlsFingerprint::Firefox => (firefox_cipher_suites(), firefox_kx_groups()),
        TlsFingerprint::Safari => (safari_cipher_suites(), safari_kx_groups()),
        TlsFingerprint::Ios => (ios_cipher_suites(), ios_kx_groups()),
        TlsFingerprint::Android => (android_cipher_suites(), android_kx_groups()),
        TlsFingerprint::Random => (random_cipher_suites(), random_kx_groups()),
        TlsFingerprint::None => return base,
    };

    CryptoProvider {
        cipher_suites,
        kx_groups,
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    }
}

/// Return the default ALPN protocol list for a given fingerprint.
///
/// Browsers always negotiate `h2` first, then fall back to `http/1.1`.
/// This is only used when the user config does not specify ALPN explicitly.
pub fn default_alpn_for(fingerprint: TlsFingerprint) -> Vec<String> {
    match fingerprint {
        TlsFingerprint::Chrome
        | TlsFingerprint::Firefox
        | TlsFingerprint::Safari
        | TlsFingerprint::Ios
        | TlsFingerprint::Android => vec!["h2".to_string(), "http/1.1".to_string()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fingerprint_variants() {
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("chrome")),
            TlsFingerprint::Chrome
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("Chrome")),
            TlsFingerprint::Chrome
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("FIREFOX")),
            TlsFingerprint::Firefox
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("safari")),
            TlsFingerprint::Safari
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("ios")),
            TlsFingerprint::Ios
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("android")),
            TlsFingerprint::Android
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("random")),
            TlsFingerprint::Random
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("randomized")),
            TlsFingerprint::Random
        );
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("none")),
            TlsFingerprint::None
        );
        assert_eq!(TlsFingerprint::from_str_opt(Some("")), TlsFingerprint::None);
        assert_eq!(
            TlsFingerprint::from_str_opt(Some("unknown")),
            TlsFingerprint::None
        );
        assert_eq!(TlsFingerprint::from_str_opt(None), TlsFingerprint::None);
    }

    #[test]
    fn chrome_provider_has_correct_suite_count() {
        let provider = make_crypto_provider(TlsFingerprint::Chrome);
        // 3 TLS 1.3 + 6 TLS 1.2 = 9
        assert_eq!(provider.cipher_suites.len(), 9);
    }

    #[test]
    fn chrome_first_suite_is_aes128() {
        let provider = make_crypto_provider(TlsFingerprint::Chrome);
        // Chrome prefers TLS13_AES_128_GCM_SHA256 first
        assert_eq!(provider.cipher_suites[0], TLS13_AES_128_GCM_SHA256,);
    }

    #[test]
    fn firefox_chacha20_before_aes256_in_tls13() {
        let provider = make_crypto_provider(TlsFingerprint::Firefox);
        // Firefox: AES128, CHACHA20, AES256 in TLS 1.3
        assert_eq!(provider.cipher_suites[0], TLS13_AES_128_GCM_SHA256);
        assert_eq!(provider.cipher_suites[1], TLS13_CHACHA20_POLY1305_SHA256);
        assert_eq!(provider.cipher_suites[2], TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn safari_kx_starts_with_p256() {
        let provider = make_crypto_provider(TlsFingerprint::Safari);
        // Safari / Apple prefers P-256 over X25519
        assert_eq!(provider.kx_groups[0].name(), kx_group::SECP256R1.name());
    }

    #[test]
    fn none_returns_default_provider() {
        let provider = make_crypto_provider(TlsFingerprint::None);
        let default = ring_provider::default_provider();
        assert_eq!(provider.cipher_suites.len(), default.cipher_suites.len());
    }

    #[test]
    fn random_shuffles_suites() {
        // Just verify it doesn't panic and returns the right count
        let provider = make_crypto_provider(TlsFingerprint::Random);
        let default = ring_provider::default_provider();
        assert_eq!(provider.cipher_suites.len(), default.cipher_suites.len());
    }
}
