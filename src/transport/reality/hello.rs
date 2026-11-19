//! uTLS-equivalent ClientHello construction.
//!
//! mihomo builds every REALITY ClientHello with uTLS from a browser preset
//! (`component/tls/utls.go` maps `client-fingerprint` names onto
//! `utls.Hello*` IDs). REALITY rides inside that hello, so matching mihomo on
//! the wire means emitting the same presets: cipher suites, extension set and
//! order, GREASE, key shares and padding. The specs below are ported from
//! metacubex/utls `u_parrots.go` at v1.9.0-alpha.1, the version mihomo Meta
//! pins.

use anyhow::{anyhow, bail, Result};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::transport::x25519mlkem768::HybridKeyShare;

/// uTLS `GREASE_PLACEHOLDER`: replaced by a per-connection GREASE value.
const GREASE: u16 = 0x0a0a;

pub(super) const X25519: u16 = 0x001d;
pub(super) const X25519MLKEM768: u16 = 0x11ec;
const X25519_KYBER768_DRAFT00: u16 = 0x6399;
const P256: u16 = 0x0017;
const P384: u16 = 0x0018;
const P521: u16 = 0x0019;
const FFDHE2048: u16 = 0x0100;
const FFDHE3072: u16 = 0x0101;

pub(super) const TLS13: u16 = 0x0304;
const TLS12: u16 = 0x0303;
const TLS11: u16 = 0x0302;
const TLS10: u16 = 0x0301;

/// Old and new ALPS (application_settings) code points.
const ALPS_OLD: u16 = 17513;
const ALPS_NEW: u16 = 17613;

const AEAD_AES_128_GCM: u16 = 0x0001;
const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

const BROTLI: u16 = 2;
const ZLIB: u16 = 1;
const ZSTD: u16 = 3;

/// Offsets into a ClientHello handshake message: type (1), length (3),
/// legacy_version (2), random (32), session ID length (1), session ID (32).
pub(super) const RANDOM: std::ops::Range<usize> = 6..38;
pub(super) const SESSION_ID: std::ops::Range<usize> = 39..71;

/// A uTLS ClientHello preset mihomo can select with `client-fingerprint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Chrome133,
    Firefox148,
    Safari26_3,
    Ios14,
    Android11OkHttp,
    Edge85,
    Qihoo360_7_5,
    Qq11_1,
    Chrome120,
    Firefox120,
    Safari16_0,
    Chrome100Psk,
    Chrome106Shuffle,
    Chrome114PaddingPskShuf,
    Chrome115Pq,
    Chrome115PqPsk,
}

impl Preset {
    /// mihomo compat: `GetFingerprint` (`component/tls/utls.go`). Empty and
    /// `none` mean "no uTLS"; names are matched exactly as written, and an
    /// unknown one logs `wrong clientFingerprint` and also means "no uTLS".
    pub fn from_name(name: Option<&str>) -> Option<Self> {
        let name = name?;
        if name.is_empty() || name == "none" {
            return None;
        }
        if name == "random" {
            let preset = random_preset();
            debug!("use initial random HelloID:{}", preset.client());
            return Some(preset);
        }
        let preset = match name {
            "chrome" => Self::Chrome133,
            "firefox" => Self::Firefox148,
            "safari" => Self::Safari26_3,
            "ios" => Self::Ios14,
            "android" => Self::Android11OkHttp,
            "edge" => Self::Edge85,
            "360" => Self::Qihoo360_7_5,
            "qq" => Self::Qq11_1,
            // classical fingerprints without X25519MLKEM768
            "chrome120" => Self::Chrome120,
            "firefox120" => Self::Firefox120,
            "safari16" => Self::Safari16_0,
            // deprecated fingerprints should not be used
            "chrome_psk" => Self::Chrome100Psk,
            "chrome_psk_shuffle" => Self::Chrome106Shuffle,
            "chrome_padding_psk_shuffle" => Self::Chrome114PaddingPskShuf,
            "chrome_pq" => Self::Chrome115Pq,
            "chrome_pq_psk" => Self::Chrome115PqPsk,
            _ => {
                warn!("wrong clientFingerprint:{name}");
                return None;
            }
        };
        debug!("use specified fingerprint:{}", preset.client());
        Some(preset)
    }

    /// uTLS `ClientHelloID.Client`: also the User-Agent of the fallback fetch.
    pub fn client(self) -> &'static str {
        match self {
            Self::Chrome133
            | Self::Chrome120
            | Self::Chrome100Psk
            | Self::Chrome106Shuffle
            | Self::Chrome114PaddingPskShuf
            | Self::Chrome115Pq
            | Self::Chrome115PqPsk => "Chrome",
            Self::Firefox148 | Self::Firefox120 => "Firefox",
            Self::Safari26_3 | Self::Safari16_0 => "Safari",
            Self::Ios14 => "iOS",
            Self::Android11OkHttp => "Android",
            Self::Edge85 => "Edge",
            Self::Qihoo360_7_5 => "360Browser",
            Self::Qq11_1 => "QQBrowser",
        }
    }
}

/// mihomo compat: `randomFingerprint` is drawn once per process, weighted
/// chrome 6, safari 3, ios 2, firefox 1.
fn random_preset() -> Preset {
    static PICK: OnceLock<Preset> = OnceLock::new();
    *PICK.get_or_init(|| {
        let preset = match OsRng.gen_range(0..12u8) {
            0..=5 => Preset::Chrome133,
            6..=8 => Preset::Safari26_3,
            9..=10 => Preset::Ios14,
            _ => Preset::Firefox148,
        };
        debug!("initial random HelloID:{}", preset.client());
        preset
    })
}

/// One entry of a key_share extension.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Share {
    /// A GREASE group with a single zero byte.
    Grease,
    /// X25519MLKEM768, its X25519 half an independent key.
    MlKem768,
    /// uTLS `ReuseHybridAndClassicalKeyShares`: X25519MLKEM768 whose X25519
    /// half the following [`Share::X25519Reused`] entry sends again.
    MlKem768Reused,
    /// X25519Kyber768Draft00: the same keys, X25519 first.
    Kyber768Draft00,
    X25519,
    X25519Reused,
    P256,
}

/// One ClientHello extension of a preset.
#[derive(Clone, PartialEq, Eq)]
enum Ext {
    Grease,
    Sni,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedCurves(Vec<u16>),
    SupportedPoints,
    SessionTicket,
    Alpn(&'static [&'static str]),
    StatusRequest,
    SignatureAlgorithms(&'static [u16]),
    Sct,
    KeyShare(Vec<Share>),
    PskKeyExchangeModes,
    SupportedVersions(&'static [u16]),
    CompressCert(&'static [u16]),
    ApplicationSettings(u16),
    GreaseEch {
        aeads: &'static [u16],
        payload_lens: &'static [u16],
    },
    Padding,
    DelegatedCredentials(&'static [u16]),
    RecordSizeLimit(u16),
}

struct Spec {
    suites: Vec<u16>,
    extensions: Vec<Ext>,
}

const H2_HTTP11: &[&str] = &["h2", "http/1.1"];

const CHROME_SUITES: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const FIREFOX_SUITES: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const SAFARI_16_SUITES: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009,
    0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const SAFARI_26_SUITES: &[u16] = &[
    GREASE, 0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009,
    0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const IOS_14_SUITES: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023,
    0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
    0xc008, 0xc012, 0x000a,
];

const CHROME_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const FIREFOX_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const FIREFOX_DELEGATED: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
/// Safari 16 and iOS 14. The duplicated 0x0805 is in the real hello.
const APPLE_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const SAFARI_26_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const VERSIONS_GREASE_13_12: &[u16] = &[GREASE, TLS13, TLS12];
const VERSIONS_GREASE_13_TO_10: &[u16] = &[GREASE, TLS13, TLS12, TLS11, TLS10];
const VERSIONS_13_12: &[u16] = &[TLS13, TLS12];

/// uTLS `BoringGREASEECH()`.
const BORING_GREASE_ECH: Ext = Ext::GreaseEch {
    aeads: &[AEAD_AES_128_GCM],
    payload_lens: &[128, 160, 192, 224],
};
const FIREFOX_GREASE_ECH: Ext = Ext::GreaseEch {
    aeads: &[AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305],
    payload_lens: &[223],
};

/// The extension list every Chrome preset from 106 to 133 is a variation of,
/// already shuffled the way Chrome shuffles it.
///
/// `hybrid` is the post-quantum group Chrome led with at the time, `alps` the
/// application_settings code point, `ech` whether GREASE ECH was sent yet, and
/// `padding` whether a padding extension follows the closing GREASE.
fn chrome_extensions(hybrid: Option<Share>, alps: u16, ech: bool, padding: bool) -> Vec<Ext> {
    let mut curves = vec![GREASE];
    let mut shares = vec![Share::Grease];
    match hybrid {
        Some(Share::Kyber768Draft00) => {
            curves.push(X25519_KYBER768_DRAFT00);
            shares.push(Share::Kyber768Draft00);
        }
        Some(share) => {
            curves.push(X25519MLKEM768);
            shares.push(share);
        }
        None => {}
    }
    curves.extend([X25519, P256, P384]);
    shares.push(Share::X25519);

    let mut extensions = vec![
        Ext::Grease,
        Ext::Sni,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedCurves(curves),
        Ext::SupportedPoints,
        Ext::SessionTicket,
        Ext::Alpn(H2_HTTP11),
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(CHROME_SIGALGS),
        Ext::Sct,
        Ext::KeyShare(shares),
        Ext::PskKeyExchangeModes,
        Ext::SupportedVersions(VERSIONS_GREASE_13_12),
        Ext::CompressCert(&[BROTLI]),
        Ext::ApplicationSettings(alps),
    ];
    if ech {
        extensions.push(BORING_GREASE_ECH);
    }
    extensions.push(Ext::Grease);
    if padding {
        extensions.push(Ext::Padding);
    }
    shuffle_chrome_extensions(extensions)
}

/// The Safari / iOS / Edge / QQ family: a fixed-order BoringSSL-style list.
fn boring_extensions(
    curves: Vec<u16>,
    session_ticket: bool,
    sigalgs: &'static [u16],
    shares: Vec<Share>,
    versions: &'static [u16],
    after_versions: &[Ext],
    padding: bool,
) -> Vec<Ext> {
    let mut extensions = vec![
        Ext::Grease,
        Ext::Sni,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedCurves(curves),
        Ext::SupportedPoints,
    ];
    if session_ticket {
        extensions.push(Ext::SessionTicket);
    }
    extensions.extend([
        Ext::Alpn(H2_HTTP11),
        Ext::StatusRequest,
        Ext::SignatureAlgorithms(sigalgs),
        Ext::Sct,
        Ext::KeyShare(shares),
        Ext::PskKeyExchangeModes,
        Ext::SupportedVersions(versions),
    ]);
    extensions.extend_from_slice(after_versions);
    extensions.push(Ext::Grease);
    if padding {
        extensions.push(Ext::Padding);
    }
    extensions
}

/// mihomo compat: uTLS `utlsIdToSpec`, with the errors `GetRealityConn` ends
/// in for the presets REALITY cannot run on.
fn spec(preset: Preset) -> Result<Spec> {
    let chrome = |extensions: Vec<Ext>| Spec {
        suites: CHROME_SUITES.to_vec(),
        extensions,
    };
    Ok(match preset {
        Preset::Chrome133 => chrome(chrome_extensions(
            Some(Share::MlKem768),
            ALPS_NEW,
            true,
            false,
        )),
        Preset::Chrome120 => chrome(chrome_extensions(None, ALPS_OLD, true, true)),
        Preset::Chrome106Shuffle => chrome(chrome_extensions(None, ALPS_OLD, false, true)),
        Preset::Chrome115Pq => chrome(chrome_extensions(
            Some(Share::Kyber768Draft00),
            ALPS_OLD,
            false,
            true,
        )),
        // These end in a pre_shared_key extension, and REALITY never has a
        // session to resume (`SessionTicketsDisabled`): uTLS refuses to build
        // the hello.
        Preset::Chrome100Psk | Preset::Chrome114PaddingPskShuf | Preset::Chrome115PqPsk => {
            bail!("tls: empty psk detected; remove the psk extension for this connection or set OmitEmptyPsk to true to conceal it in utls")
        }
        Preset::Firefox148 => Spec {
            suites: FIREFOX_SUITES.to_vec(),
            extensions: vec![
                Ext::Sni,
                Ext::ExtendedMasterSecret,
                Ext::RenegotiationInfo,
                Ext::SupportedCurves(vec![
                    X25519MLKEM768,
                    X25519,
                    P256,
                    P384,
                    P521,
                    FFDHE2048,
                    FFDHE3072,
                ]),
                Ext::SupportedPoints,
                Ext::Alpn(H2_HTTP11),
                Ext::StatusRequest,
                Ext::DelegatedCredentials(FIREFOX_DELEGATED),
                Ext::Sct,
                Ext::KeyShare(vec![
                    Share::MlKem768Reused,
                    Share::X25519Reused,
                    Share::P256,
                ]),
                Ext::SupportedVersions(VERSIONS_13_12),
                Ext::SignatureAlgorithms(FIREFOX_SIGALGS),
                Ext::RecordSizeLimit(0x4001),
                Ext::CompressCert(&[ZLIB, BROTLI, ZSTD]),
                FIREFOX_GREASE_ECH,
            ],
        },
        Preset::Firefox120 => Spec {
            suites: FIREFOX_SUITES.to_vec(),
            extensions: vec![
                Ext::Sni,
                Ext::ExtendedMasterSecret,
                Ext::RenegotiationInfo,
                Ext::SupportedCurves(vec![X25519, P256, P384, P521, FFDHE2048, FFDHE3072]),
                Ext::SupportedPoints,
                Ext::SessionTicket,
                Ext::Alpn(H2_HTTP11),
                Ext::StatusRequest,
                Ext::DelegatedCredentials(FIREFOX_DELEGATED),
                Ext::KeyShare(vec![Share::X25519, Share::P256]),
                Ext::SupportedVersions(VERSIONS_13_12),
                Ext::SignatureAlgorithms(FIREFOX_SIGALGS),
                Ext::PskKeyExchangeModes,
                Ext::RecordSizeLimit(0x4001),
                FIREFOX_GREASE_ECH,
            ],
        },
        Preset::Safari26_3 => Spec {
            suites: SAFARI_26_SUITES.to_vec(),
            extensions: boring_extensions(
                vec![GREASE, X25519MLKEM768, X25519, P256, P384, P521],
                false,
                SAFARI_26_SIGALGS,
                vec![Share::Grease, Share::MlKem768, Share::X25519],
                VERSIONS_GREASE_13_12,
                &[Ext::CompressCert(&[ZLIB])],
                false,
            ),
        },
        Preset::Safari16_0 => Spec {
            suites: SAFARI_16_SUITES.to_vec(),
            extensions: boring_extensions(
                vec![GREASE, X25519, P256, P384, P521],
                false,
                APPLE_SIGALGS,
                vec![Share::Grease, Share::X25519],
                VERSIONS_GREASE_13_TO_10,
                &[Ext::CompressCert(&[ZLIB])],
                true,
            ),
        },
        Preset::Ios14 => Spec {
            suites: IOS_14_SUITES.to_vec(),
            extensions: boring_extensions(
                vec![GREASE, X25519, P256, P384, P521],
                false,
                APPLE_SIGALGS,
                vec![Share::Grease, Share::X25519],
                VERSIONS_GREASE_13_TO_10,
                &[],
                true,
            ),
        },
        Preset::Edge85 => Spec {
            suites: CHROME_SUITES.to_vec(),
            extensions: boring_extensions(
                vec![GREASE, X25519, P256, P384],
                true,
                CHROME_SIGALGS,
                vec![Share::Grease, Share::X25519],
                VERSIONS_GREASE_13_TO_10,
                &[Ext::CompressCert(&[BROTLI])],
                true,
            ),
        },
        Preset::Qq11_1 => Spec {
            suites: CHROME_SUITES.to_vec(),
            extensions: boring_extensions(
                vec![GREASE, X25519, P256, P384],
                true,
                CHROME_SIGALGS,
                vec![Share::Grease, Share::X25519],
                VERSIONS_GREASE_13_TO_10,
                &[
                    Ext::CompressCert(&[BROTLI]),
                    Ext::ApplicationSettings(ALPS_OLD),
                ],
                true,
            ),
        },
        // HelloAndroid_11_OkHttp and Hello360_7_5 carry neither
        // supported_versions nor key_share: uTLS builds a TLS 1.2 hello,
        // `KeyShareKeys` stays empty, and `GetRealityConn` gives up with this
        // after its retries.
        Preset::Android11OkHttp | Preset::Qihoo360_7_5 => bail!("nil ecdheKey"),
    })
}

/// mihomo compat: uTLS `ShuffleChromeTLSExtensions` — a Fisher-Yates pass in
/// which GREASE and padding keep their positions.
fn shuffle_chrome_extensions(mut extensions: Vec<Ext>) -> Vec<Ext> {
    let pinned = |ext: &Ext| matches!(ext, Ext::Grease | Ext::Padding);
    for i in (1..extensions.len()).rev() {
        let j = OsRng.gen_range(0..=i);
        if !pinned(&extensions[i]) && !pinned(&extensions[j]) {
            extensions.swap(i, j);
        }
    }
    extensions
}

/// The private keys behind a hello's key shares (uTLS `KeySharePrivateKeys`).
pub(super) struct HelloKeys {
    /// `Ecdhe`: the X25519 key of the first classical share.
    pub ecdhe: Option<StaticSecret>,
    /// `Mlkem` + `MlkemEcdhe`.
    pub hybrid: Option<HybridKeyShare>,
}

/// A ClientHello ready for REALITY to seal its session ID into.
pub(super) struct ClientHello {
    /// The handshake message (type, length, body) with a zeroed session ID.
    pub raw: Vec<u8>,
    pub keys: HelloKeys,
    /// TLS 1.3 cipher suites offered.
    pub suites: Vec<u16>,
    /// Groups a key share was sent for.
    pub share_groups: Vec<u16>,
    /// The ALPS code point offered, if any. A server that accepts it expects
    /// the client's own EncryptedExtensions before Finished.
    pub alps: Option<u16>,
}

/// BoringSSL GREASE values for one connection (uTLS `greaseSeed`).
struct Grease {
    cipher: u16,
    group: u16,
    extension1: u16,
    extension2: u16,
    version: u16,
}

impl Grease {
    fn generate() -> Self {
        // uTLS `GetBoringGREASEValue`: 0xωaωa for a random nibble ω.
        let value = |seed: u16| {
            let low = (seed & 0xf0) | 0x0a;
            low | (low << 8)
        };
        let mut seed = [0u16; 5];
        for slot in &mut seed {
            *slot = OsRng.next_u32() as u16;
        }
        // The two GREASE extensions must not share a type.
        if value(seed[2]) == value(seed[3]) {
            seed[3] ^= 0x1010;
        }
        Self {
            cipher: value(seed[0]),
            group: value(seed[1]),
            extension1: value(seed[2]),
            extension2: value(seed[3]),
            version: value(seed[4]),
        }
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// mihomo compat: Go `hostnameInSNI` — IP literals are not sent as SNI, and
/// trailing dots are dropped.
fn hostname_in_sni(name: &str) -> &str {
    let mut host = name;
    if host.len() > 1 && host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    if let Some(zone) = host.rfind('%').filter(|&at| at > 0) {
        host = &host[..zone];
    }
    if host.parse::<IpAddr>().is_ok() {
        return "";
    }
    name.trim_end_matches('.')
}

/// Append one extension: type, length, body.
fn put_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// A list of big-endian u16s behind a length prefix of `prefix_len` bytes.
fn u16_list(values: impl IntoIterator<Item = u16>, prefix_len: usize) -> Vec<u8> {
    let values: Vec<u8> = values.into_iter().flat_map(u16::to_be_bytes).collect();
    let mut body = Vec::with_capacity(prefix_len + values.len());
    match prefix_len {
        1 => body.push(values.len() as u8),
        _ => body.extend_from_slice(&(values.len() as u16).to_be_bytes()),
    }
    body.extend_from_slice(&values);
    body
}

/// A list of protocol names, each behind a one-byte length, behind a u16 total.
fn protocol_list(protocols: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        list.push(protocol.len() as u8);
        list.extend_from_slice(protocol.as_bytes());
    }
    let mut body = (list.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&list);
    body
}

/// uTLS `BoringPaddingStyle`: pad a 256..511-byte hello up to 512 bytes.
fn boring_padding(unpadded_len: usize) -> Option<usize> {
    if unpadded_len > 0xff && unpadded_len < 0x200 {
        let padding = 0x200 - unpadded_len;
        return Some(if padding >= 4 + 1 { padding - 4 } else { 1 });
    }
    None
}

/// Build a ClientHello for `preset`.
///
/// mihomo compat: uTLS `BuildHandshakeState` + `ApplyPreset`, and — unless
/// `keep_mlkem768` — `BuildRemovedX25519MLKEM768HandshakeState`, which strips
/// the hybrid group out of supported_groups and key_share for REALITY servers
/// that predate it.
pub(super) fn build(preset: Preset, server_name: &str, keep_mlkem768: bool) -> Result<ClientHello> {
    let Spec { suites, extensions } = spec(preset)?;
    let grease = Grease::generate();

    let suites: Vec<u16> = suites
        .into_iter()
        .map(|suite| {
            if suite == GREASE {
                grease.cipher
            } else {
                suite
            }
        })
        .collect();

    let mut keys = HelloKeys {
        ecdhe: None,
        hybrid: None,
    };
    let mut share_groups = Vec::new();
    let mut alps = None;
    let mut grease_extensions = 0;
    let mut body = Vec::with_capacity(2048);
    // Where the padding extension goes, once the rest of the hello is known.
    let mut padding_at = None;

    for extension in &extensions {
        match extension {
            Ext::Grease => {
                grease_extensions += 1;
                match grease_extensions {
                    1 => put_extension(&mut body, grease.extension1, &[]),
                    2 => put_extension(&mut body, grease.extension2, &[0]),
                    _ => bail!("at most 2 grease extensions are supported"),
                }
            }
            Ext::Sni => {
                let host = hostname_in_sni(server_name);
                if !host.is_empty() {
                    let mut name = vec![0u8]; // host_name
                    name.extend_from_slice(&(host.len() as u16).to_be_bytes());
                    name.extend_from_slice(host.as_bytes());
                    let mut list = (name.len() as u16).to_be_bytes().to_vec();
                    list.extend_from_slice(&name);
                    put_extension(&mut body, 0, &list);
                }
            }
            Ext::ExtendedMasterSecret => put_extension(&mut body, 23, &[]),
            Ext::RenegotiationInfo => put_extension(&mut body, 0xff01, &[0]),
            Ext::SupportedCurves(curves) => {
                let curves = curves
                    .iter()
                    .filter(|&&curve| keep_mlkem768 || curve != X25519MLKEM768)
                    .map(|&curve| if curve == GREASE { grease.group } else { curve });
                put_extension(&mut body, 10, &u16_list(curves, 2));
            }
            Ext::SupportedPoints => put_extension(&mut body, 11, &[1, 0]),
            Ext::SessionTicket => put_extension(&mut body, 35, &[]),
            Ext::Alpn(protocols) => put_extension(&mut body, 16, &protocol_list(protocols)),
            Ext::StatusRequest => put_extension(&mut body, 5, &[1, 0, 0, 0, 0]),
            Ext::SignatureAlgorithms(schemes) => {
                put_extension(&mut body, 13, &u16_list(schemes.iter().copied(), 2));
            }
            Ext::Sct => put_extension(&mut body, 18, &[]),
            Ext::KeyShare(shares) => {
                let mut list = Vec::new();
                let mut put_share = |group: u16, data: &[u8]| {
                    list.extend_from_slice(&group.to_be_bytes());
                    list.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    list.extend_from_slice(data);
                };
                for share in shares {
                    match share {
                        Share::Grease => put_share(grease.group, &[0]),
                        Share::MlKem768 | Share::MlKem768Reused | Share::Kyber768Draft00 => {
                            if !keep_mlkem768 && *share != Share::Kyber768Draft00 {
                                continue;
                            }
                            let hybrid = HybridKeyShare::generate();
                            let mut data = hybrid.encapsulation_key();
                            let group = if *share == Share::Kyber768Draft00 {
                                data.splice(0..0, hybrid.x25519_public());
                                X25519_KYBER768_DRAFT00
                            } else {
                                data.extend_from_slice(&hybrid.x25519_public());
                                X25519MLKEM768
                            };
                            put_share(group, &data);
                            share_groups.push(group);
                            keys.hybrid = Some(hybrid);
                        }
                        Share::X25519 | Share::X25519Reused => {
                            // With the hybrid share stripped there is no key
                            // on the wire to match, so a fresh one will do.
                            let reused = (*share == Share::X25519Reused)
                                .then_some(keys.hybrid.as_ref())
                                .flatten()
                                .map(|hybrid| hybrid.x25519_secret().clone());
                            let secret =
                                reused.unwrap_or_else(|| StaticSecret::random_from_rng(OsRng));
                            put_share(X25519, PublicKey::from(&secret).as_bytes());
                            share_groups.push(X25519);
                            keys.ecdhe.get_or_insert(secret);
                        }
                        Share::P256 => {
                            let rng = ring::rand::SystemRandom::new();
                            let public = ring::agreement::EphemeralPrivateKey::generate(
                                &ring::agreement::ECDH_P256,
                                &rng,
                            )
                            .and_then(|key| key.compute_public_key())
                            .map_err(|_| anyhow!("generating a P-256 key share failed"))?;
                            put_share(P256, public.as_ref());
                            share_groups.push(P256);
                        }
                    }
                }
                let mut shares = (list.len() as u16).to_be_bytes().to_vec();
                shares.extend_from_slice(&list);
                put_extension(&mut body, 51, &shares);
            }
            Ext::PskKeyExchangeModes => put_extension(&mut body, 45, &[1, 1]),
            Ext::SupportedVersions(versions) => {
                let versions = versions.iter().map(|&version| {
                    if version == GREASE {
                        grease.version
                    } else {
                        version
                    }
                });
                put_extension(&mut body, 43, &u16_list(versions, 1));
            }
            Ext::CompressCert(algorithms) => {
                put_extension(&mut body, 27, &u16_list(algorithms.iter().copied(), 1));
            }
            Ext::ApplicationSettings(code_point) => {
                alps = Some(*code_point);
                put_extension(&mut body, *code_point, &protocol_list(&["h2"]));
            }
            Ext::GreaseEch {
                aeads,
                payload_lens,
            } => {
                // uTLS `GREASEEncryptedClientHelloExtension`: an outer hello
                // with a random config ID, a fresh X25519 point for `enc`, and
                // a random payload the size of a sealed inner hello.
                let aead = aeads[OsRng.gen_range(0..aeads.len())];
                let payload_len = payload_lens[OsRng.gen_range(0..payload_lens.len())] + 16;
                let enc = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
                let mut ech = vec![0u8]; // OuterClientHello
                ech.extend_from_slice(&[0x00, 0x01]); // HKDF-SHA256
                ech.extend_from_slice(&aead.to_be_bytes());
                ech.push(random_bytes::<1>()[0]);
                ech.extend_from_slice(&32u16.to_be_bytes());
                ech.extend_from_slice(enc.as_bytes());
                ech.extend_from_slice(&payload_len.to_be_bytes());
                let mut payload = vec![0u8; payload_len as usize];
                OsRng.fill_bytes(&mut payload);
                ech.extend_from_slice(&payload);
                put_extension(&mut body, 0xfe0d, &ech);
            }
            Ext::Padding => padding_at = Some(body.len()),
            Ext::DelegatedCredentials(schemes) => {
                put_extension(&mut body, 34, &u16_list(schemes.iter().copied(), 2));
            }
            Ext::RecordSizeLimit(limit) => put_extension(&mut body, 28, &limit.to_be_bytes()),
        }
    }

    // version, random, session ID, cipher suites, compression methods
    let header_len = 2 + 32 + 1 + 32 + 2 + suites.len() * 2 + 1 + 1;
    if let Some(at) = padding_at {
        // uTLS `MarshalClientHelloNoECH`: the unpadded length counts the
        // handshake header and the extensions length field.
        if let Some(padding) = boring_padding(header_len + 4 + body.len() + 2) {
            let mut extension = Vec::with_capacity(4 + padding);
            put_extension(&mut extension, 21, &vec![0u8; padding]);
            body.splice(at..at, extension);
        }
    }

    let hello_len = header_len + 2 + body.len();
    let mut raw = Vec::with_capacity(4 + hello_len);
    raw.push(0x01); // ClientHello
    raw.extend_from_slice(&(hello_len as u32).to_be_bytes()[1..]);
    raw.extend_from_slice(&TLS12.to_be_bytes());
    raw.extend_from_slice(&random_bytes::<32>());
    raw.push(32);
    raw.extend_from_slice(&[0u8; 32]);
    raw.extend_from_slice(&u16_list(suites.iter().copied(), 2));
    raw.extend_from_slice(&[1, 0]); // compression: none
    raw.extend_from_slice(&(body.len() as u16).to_be_bytes());
    raw.extend_from_slice(&body);

    Ok(ClientHello {
        raw,
        keys,
        suites: suites
            .into_iter()
            .filter(|suite| (0x1301..=0x1303).contains(suite))
            .collect(),
        share_groups,
        alps,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// `(type, body)` of every extension in a ClientHello, in wire order.
    pub(crate) fn extensions(hello: &[u8]) -> Vec<(u16, &[u8])> {
        let u16_at = |at: usize| u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
        let mut offset = SESSION_ID.end;
        offset += 2 + u16_at(offset); // cipher suites
        offset += 1 + hello[offset] as usize; // compression methods
        let end = offset + 2 + u16_at(offset);
        assert_eq!(end, hello.len());
        offset += 2;

        let mut extensions = Vec::new();
        while offset < end {
            let body = offset + 4..offset + 4 + u16_at(offset + 2);
            extensions.push((u16_at(offset) as u16, &hello[body.clone()]));
            offset = body.end;
        }
        extensions
    }

    pub(crate) fn extension(hello: &[u8], kind: u16) -> Option<&[u8]> {
        extensions(hello)
            .into_iter()
            .find(|(found, _)| *found == kind)
            .map(|(_, body)| body)
    }

    /// `(group, key)` of every key share a ClientHello offers, in wire order.
    pub(crate) fn key_shares(hello: &[u8]) -> Vec<(u16, &[u8])> {
        let mut entries = &extension(hello, 51).unwrap()[2..];
        let mut shares = Vec::new();
        while !entries.is_empty() {
            let group = u16::from_be_bytes([entries[0], entries[1]]);
            let len = u16::from_be_bytes([entries[2], entries[3]]) as usize;
            shares.push((group, &entries[4..4 + len]));
            entries = &entries[4 + len..];
        }
        shares
    }

    fn cipher_suites(hello: &[u8]) -> Vec<u16> {
        let len = u16::from_be_bytes([hello[71], hello[72]]) as usize;
        hello[73..73 + len]
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect()
    }

    fn u16s(bytes: &[u8]) -> Vec<u16> {
        bytes
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect()
    }

    fn is_grease(value: u16) -> bool {
        (value >> 8) == (value & 0xff) && value & 0xf == 0xa
    }

    #[test]
    fn fingerprint_names_follow_mihomo() {
        // component/tls/utls.go `fingerprints`.
        for (name, preset) in [
            ("chrome", Preset::Chrome133),
            ("firefox", Preset::Firefox148),
            ("safari", Preset::Safari26_3),
            ("ios", Preset::Ios14),
            ("android", Preset::Android11OkHttp),
            ("edge", Preset::Edge85),
            ("360", Preset::Qihoo360_7_5),
            ("qq", Preset::Qq11_1),
            ("chrome120", Preset::Chrome120),
            ("firefox120", Preset::Firefox120),
            ("safari16", Preset::Safari16_0),
            ("chrome_psk", Preset::Chrome100Psk),
            ("chrome_psk_shuffle", Preset::Chrome106Shuffle),
            (
                "chrome_padding_psk_shuffle",
                Preset::Chrome114PaddingPskShuf,
            ),
            ("chrome_pq", Preset::Chrome115Pq),
            ("chrome_pq_psk", Preset::Chrome115PqPsk),
        ] {
            assert_eq!(Preset::from_name(Some(name)), Some(preset), "{name}");
        }
        // `random` settles on one of four presets for the process lifetime.
        let random = Preset::from_name(Some("random")).unwrap();
        assert!(matches!(
            random,
            Preset::Chrome133 | Preset::Safari26_3 | Preset::Ios14 | Preset::Firefox148
        ));
        assert_eq!(Preset::from_name(Some("random")), Some(random));
        // No uTLS: absent, empty, `none`, and anything GetFingerprint rejects.
        for name in [None, Some(""), Some("none"), Some("Chrome"), Some("opera")] {
            assert_eq!(Preset::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn chrome_133_matches_the_utls_preset() {
        let hello = build(Preset::Chrome133, "example.com", true).unwrap();
        let raw = &hello.raw;
        assert_eq!(raw[0], 0x01);
        assert_eq!(
            u32::from_be_bytes([0, raw[1], raw[2], raw[3]]) as usize,
            raw.len() - 4
        );
        assert_eq!(&raw[4..6], &[0x03, 0x03]);
        assert_eq!(raw[38], 32);
        assert_eq!(&raw[SESSION_ID], &[0u8; 32]);

        let suites = cipher_suites(raw);
        assert!(is_grease(suites[0]));
        assert_eq!(&suites[1..], &CHROME_SUITES[1..]);
        assert_eq!(hello.suites, [0x1301, 0x1302, 0x1303]);

        // GREASE opens and closes the list; everything between is shuffled.
        let extensions = extensions(raw);
        let (first, last) = (extensions[0], extensions[extensions.len() - 1]);
        assert!(is_grease(first.0) && first.1.is_empty());
        assert!(is_grease(last.0) && last.1 == [0]);
        assert_ne!(first.0, last.0);
        let mut kinds: Vec<u16> = extensions[1..extensions.len() - 1]
            .iter()
            .map(|(kind, _)| *kind)
            .collect();
        kinds.sort_unstable();
        assert_eq!(
            kinds,
            [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, ALPS_NEW, 0xfe0d, 0xff01]
        );

        assert_eq!(
            extension(raw, 0).unwrap(),
            b"\x00\x0e\x00\x00\x0bexample.com"
        );
        assert_eq!(extension(raw, 16).unwrap(), b"\x00\x0c\x02h2\x08http/1.1");
        assert_eq!(extension(raw, ALPS_NEW).unwrap(), b"\x00\x03\x02h2");
        assert_eq!(extension(raw, 27).unwrap(), [2, 0, 2]);
        assert_eq!(extension(raw, 5).unwrap(), [1, 0, 0, 0, 0]);
        assert_eq!(extension(raw, 45).unwrap(), [1, 1]);
        assert_eq!(extension(raw, 11).unwrap(), [1, 0]);
        assert_eq!(extension(raw, 0xff01).unwrap(), [0]);
        assert_eq!(
            u16s(&extension(raw, 13).unwrap()[2..]),
            CHROME_SIGALGS.to_vec()
        );

        let groups = u16s(&extension(raw, 10).unwrap()[2..]);
        assert!(is_grease(groups[0]));
        assert_eq!(&groups[1..], [X25519MLKEM768, X25519, P256, P384]);

        let versions = u16s(&extension(raw, 43).unwrap()[1..]);
        assert!(is_grease(versions[0]));
        assert_eq!(&versions[1..], [TLS13, TLS12]);

        // GREASE, then the hybrid share, then an X25519 share with a key of
        // its own: Chrome does not reuse the hybrid's X25519 half.
        let shares = key_shares(raw);
        assert_eq!(shares.len(), 3);
        assert_eq!((shares[0].0, shares[0].1), (groups[0], [0u8].as_slice()));
        assert_eq!(
            (shares[1].0, shares[1].1.len()),
            (X25519MLKEM768, 1184 + 32)
        );
        assert_eq!((shares[2].0, shares[2].1.len()), (X25519, 32));
        assert_ne!(shares[2].1, &shares[1].1[1184..]);
        assert_eq!(hello.share_groups, [X25519MLKEM768, X25519]);
        assert_eq!(hello.alps, Some(ALPS_NEW));

        let ecdhe = hello.keys.ecdhe.as_ref().unwrap();
        assert_eq!(PublicKey::from(ecdhe).as_bytes(), shares[2].1);
        let hybrid = hello.keys.hybrid.as_ref().unwrap();
        assert_eq!(hybrid.x25519_public(), shares[1].1[1184..]);

        // GREASE ECH: outer hello, HKDF-SHA256 + AES-128-GCM, 32-byte enc.
        let ech = extension(raw, 0xfe0d).unwrap();
        assert_eq!(&ech[..5], [0, 0, 1, 0, 1]);
        assert_eq!(&ech[6..8], [0, 32]);
        let payload_len = u16::from_be_bytes([ech[40], ech[41]]) as usize;
        assert!([144, 176, 208, 240].contains(&payload_len));
        assert_eq!(ech.len(), 42 + payload_len);
    }

    #[test]
    fn chrome_shuffles_its_extensions_between_connections() {
        let order = |_| {
            let hello = build(Preset::Chrome133, "example.com", true).unwrap();
            extensions(&hello.raw)
                .iter()
                .map(|(kind, _)| *kind)
                .filter(|kind| !is_grease(*kind))
                .collect::<Vec<_>>()
        };
        let orders: Vec<_> = (0..8).map(order).collect();
        assert!(orders.iter().any(|other| *other != orders[0]));
    }

    #[test]
    fn dropping_mlkem768_leaves_a_lone_x25519_share() {
        // BuildRemovedX25519MLKEM768HandshakeState.
        let hello = build(Preset::Chrome133, "example.com", false).unwrap();
        let groups = u16s(&extension(&hello.raw, 10).unwrap()[2..]);
        assert_eq!(&groups[1..], [X25519, P256, P384]);
        let shares = key_shares(&hello.raw);
        assert_eq!(shares.len(), 2);
        assert!(is_grease(shares[0].0));
        assert_eq!((shares[1].0, shares[1].1.len()), (X25519, 32));
        assert!(hello.keys.hybrid.is_none());
        assert_eq!(hello.share_groups, [X25519]);
    }

    #[test]
    fn firefox_148_reuses_the_hybrid_x25519_key() {
        let hello = build(Preset::Firefox148, "example.com", true).unwrap();
        let raw = &hello.raw;
        assert_eq!(cipher_suites(raw), FIREFOX_SUITES);
        let kinds: Vec<u16> = extensions(raw).iter().map(|(kind, _)| *kind).collect();
        assert_eq!(
            kinds,
            [0, 23, 0xff01, 10, 11, 16, 5, 34, 18, 51, 43, 13, 28, 27, 0xfe0d]
        );
        assert_eq!(
            u16s(&extension(raw, 10).unwrap()[2..]),
            [
                X25519MLKEM768,
                X25519,
                P256,
                P384,
                P521,
                FFDHE2048,
                FFDHE3072
            ]
        );
        assert_eq!(extension(raw, 28).unwrap(), [0x40, 0x01]);
        assert_eq!(extension(raw, 27).unwrap(), [6, 0, 1, 0, 2, 0, 3]);
        assert_eq!(extension(raw, 43).unwrap(), [4, 3, 4, 3, 3]);

        let shares = key_shares(raw);
        assert_eq!(
            shares.iter().map(|(group, _)| *group).collect::<Vec<_>>(),
            [X25519MLKEM768, X25519, P256]
        );
        assert_eq!(shares[1].1, &shares[0].1[1184..]);
        assert_eq!(shares[2].1.len(), 65);
        assert_eq!(shares[2].1[0], 0x04);

        // Without the hybrid share there is nothing to reuse.
        let hello = build(Preset::Firefox148, "example.com", false).unwrap();
        let shares = key_shares(&hello.raw);
        assert_eq!(
            shares.iter().map(|(group, _)| *group).collect::<Vec<_>>(),
            [X25519, P256]
        );
        assert!(hello.keys.ecdhe.is_some() && hello.keys.hybrid.is_none());
    }

    #[test]
    fn safari_and_ios_presets_keep_their_fixed_order() {
        let hello = build(Preset::Safari26_3, "example.com", true).unwrap();
        let suites = cipher_suites(&hello.raw);
        assert_eq!(&suites[1..], &SAFARI_26_SUITES[1..]);
        let kinds: Vec<u16> = extensions(&hello.raw)
            .iter()
            .map(|(kind, _)| *kind)
            .collect();
        assert!(is_grease(kinds[0]) && is_grease(kinds[kinds.len() - 1]));
        assert_eq!(
            &kinds[1..kinds.len() - 1],
            [0, 23, 0xff01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]
        );
        assert_eq!(extension(&hello.raw, 27).unwrap(), [2, 0, 1]);
        let shares = key_shares(&hello.raw);
        assert_ne!(shares[2].1, &shares[1].1[1184..]);

        let hello = build(Preset::Ios14, "example.com", true).unwrap();
        assert_eq!(&cipher_suites(&hello.raw)[1..], &IOS_14_SUITES[1..]);
        let versions = u16s(&extension(&hello.raw, 43).unwrap()[1..]);
        assert_eq!(&versions[1..], [TLS13, TLS12, TLS11, TLS10]);
        assert!(hello.keys.hybrid.is_none());
        assert_eq!(hello.share_groups, [X25519]);
    }

    #[test]
    fn padded_presets_fill_the_hello_to_512_bytes() {
        // BoringPaddingStyle: 256..511 bytes are padded to exactly 512.
        for preset in [
            Preset::Ios14,
            Preset::Safari16_0,
            Preset::Edge85,
            Preset::Qq11_1,
            Preset::Chrome106Shuffle,
        ] {
            let hello = build(preset, "example.com", true).unwrap();
            assert_eq!(hello.raw.len(), 512, "{preset:?}");
            let padding = extension(&hello.raw, 21).unwrap();
            assert!(padding.iter().all(|&byte| byte == 0), "{preset:?}");
        }
        // Chrome 120's GREASE ECH pushes it past the padded range, unless
        // the ECH payload came out at its shortest.
        for _ in 0..16 {
            let hello = build(Preset::Chrome120, "example.com", true).unwrap();
            assert!(hello.raw.len() >= 512);
            assert_eq!(extension(&hello.raw, 21).is_some(), hello.raw.len() == 512);
        }
        // The Kyber presets are far past it too, and send X25519 first.
        let hello = build(Preset::Chrome115Pq, "example.com", true).unwrap();
        assert!(extension(&hello.raw, 21).is_none());
        let shares = key_shares(&hello.raw);
        assert_eq!((shares[1].0, shares[1].1.len()), (0x6399, 32 + 1184));
        assert_eq!(
            hello.keys.hybrid.as_ref().unwrap().x25519_public(),
            shares[1].1[..32]
        );
    }

    #[test]
    fn padding_follows_boringssl() {
        assert_eq!(boring_padding(0xff), None);
        assert_eq!(boring_padding(0x100), Some(0x100 - 4));
        assert_eq!(boring_padding(0x1fb), Some(1));
        assert_eq!(boring_padding(0x1fc), Some(1));
        assert_eq!(boring_padding(0x1ff), Some(1));
        assert_eq!(boring_padding(0x200), None);
    }

    #[test]
    fn presets_reality_cannot_run_on_fail_like_mihomo() {
        // TLS 1.2-only: no key share to authenticate with.
        for preset in [Preset::Android11OkHttp, Preset::Qihoo360_7_5] {
            let error = build(preset, "example.com", true).err().unwrap();
            assert_eq!(error.to_string(), "nil ecdheKey");
        }
        // A pre_shared_key extension with no session behind it.
        for preset in [
            Preset::Chrome100Psk,
            Preset::Chrome114PaddingPskShuf,
            Preset::Chrome115PqPsk,
        ] {
            let error = build(preset, "example.com", true).err().unwrap();
            assert!(error.to_string().starts_with("tls: empty psk detected;"));
        }
    }

    #[test]
    fn ip_literals_are_not_sent_as_sni() {
        for name in ["192.0.2.1", "[2001:db8::1]", "fe80::1%eth0"] {
            let hello = build(Preset::Chrome133, name, true).unwrap();
            assert!(extension(&hello.raw, 0).is_none(), "{name}");
        }
        let hello = build(Preset::Chrome133, "example.com.", true).unwrap();
        assert_eq!(
            extension(&hello.raw, 0).unwrap(),
            b"\x00\x0e\x00\x00\x0bexample.com"
        );
    }
}
