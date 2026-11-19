//! anytls padding scheme (mihomo transport/anytls/padding/padding.go).
//!
//! A padding scheme is a text document keyed by packet index. For each packet
//! index up to `stop`, the scheme specifies how the record is chopped into
//! pieces whose sizes come from a numeric range (or a "c" marker meaning
//! "continue only if payload remains").

use md5::{Digest, Md5};
use parking_lot::RwLock;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;

/// Sentinel value returned for the "c" (check) marker in a padding scheme.
/// Semantics match mihomo's CheckMark constant.
pub const CHECK_MARK: i32 = -1;

/// The padding factory a client and all of its sessions share, swapped whole
/// when the server pushes a new scheme.
/// mihomo compat: client.go `Client.padding`, an `atomic.Pointer` every
/// session is handed, so an update reaches the sessions dialed after it.
pub type SharedPadding = Arc<RwLock<Arc<PaddingFactory>>>;

/// Hex MD5 of a raw scheme, as carried in the `padding-md5` setting.
pub fn scheme_md5(raw_scheme: &[u8]) -> String {
    format!("{:x}", Md5::digest(raw_scheme))
}

/// mihomo padding.UpdatePaddingScheme: replace the shared factory if
/// `raw_scheme` parses.
pub fn update_padding_scheme(raw_scheme: &[u8], to: &SharedPadding) -> bool {
    match PaddingFactory::new(raw_scheme) {
        Some(factory) => {
            *to.write() = Arc::new(factory);
            true
        }
        None => false,
    }
}

/// Default padding scheme shipped with mihomo.
pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

#[derive(Debug)]
pub struct PaddingFactory {
    pub stop: u32,
    pub md5_hex: String,
    scheme: HashMap<String, String>,
}

impl PaddingFactory {
    pub fn new(raw_scheme: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw_scheme).ok()?;
        let mut scheme = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                scheme.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        if scheme.is_empty() {
            return None;
        }
        let stop = scheme.get("stop")?.parse::<u32>().ok()?;
        let md5_hex = scheme_md5(raw_scheme);
        Some(Self {
            stop,
            md5_hex,
            scheme,
        })
    }

    pub fn default_scheme() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME).expect("default padding scheme parses")
    }

    /// Generate packet sizes for packet counter `pkt`. Returns empty vec when
    /// no entry is defined for that index. `CHECK_MARK` entries stand in for
    /// the "c" continuation markers.
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let mut out = Vec::new();
        let key = pkt.to_string();
        let Some(s) = self.scheme.get(&key) else {
            return out;
        };
        let mut rng = rand::thread_rng();
        for range in s.split(',') {
            let range = range.trim();
            if range == "c" {
                out.push(CHECK_MARK);
                continue;
            }
            let Some((lo, hi)) = range.split_once('-') else {
                continue;
            };
            let Ok(mut a) = lo.trim().parse::<i64>() else {
                continue;
            };
            let Ok(mut b) = hi.trim().parse::<i64>() else {
                continue;
            };
            if a > b {
                std::mem::swap(&mut a, &mut b);
            }
            if a <= 0 || b <= 0 {
                continue;
            }
            if a == b {
                out.push(a as i32);
            } else {
                // mihomo compat: rand.Int(rand.Reader, big.NewInt(b-a)) yields [0, b-a).
                let r = rng.gen_range(0..(b - a));
                out.push((r + a) as i32);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_parses() {
        let p = PaddingFactory::default_scheme();
        assert_eq!(p.stop, 8);
        assert!(!p.md5_hex.is_empty());
    }

    #[test]
    fn fixed_range() {
        let p = PaddingFactory::default_scheme();
        let sizes = p.generate_record_payload_sizes(0);
        assert_eq!(sizes, vec![30]);
    }

    #[test]
    fn continuation_marker() {
        let p = PaddingFactory::default_scheme();
        let sizes = p.generate_record_payload_sizes(2);
        // "400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000"
        assert_eq!(sizes.len(), 9);
        assert_eq!(sizes[1], CHECK_MARK);
        assert_eq!(sizes[3], CHECK_MARK);
    }

    #[test]
    fn undefined_packet_empty() {
        let p = PaddingFactory::default_scheme();
        assert!(p.generate_record_payload_sizes(99).is_empty());
    }

    /// padding.go UpdatePaddingScheme: a scheme that parses replaces the
    /// shared factory; one that does not leaves it alone.
    #[test]
    fn update_swaps_the_shared_factory_only_for_a_valid_scheme() {
        let shared: SharedPadding =
            Arc::new(RwLock::new(Arc::new(PaddingFactory::default_scheme())));
        let raw = b"stop=2\n0=40-40\n1=64-64";
        assert!(update_padding_scheme(raw, &shared));
        assert_eq!(shared.read().stop, 2);
        assert_eq!(shared.read().md5_hex, scheme_md5(raw));
        assert_eq!(shared.read().generate_record_payload_sizes(0), vec![40]);

        // No `stop`, and not a scheme at all.
        assert!(!update_padding_scheme(b"0=40-40", &shared));
        assert!(!update_padding_scheme(b"", &shared));
        assert_eq!(shared.read().md5_hex, scheme_md5(raw));
    }
}
