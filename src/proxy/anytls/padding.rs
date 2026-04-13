//! anytls padding scheme (mihomo transport/anytls/padding/padding.go).
//!
//! A padding scheme is a text document keyed by packet index. For each packet
//! index up to `stop`, the scheme specifies how the record is chopped into
//! pieces whose sizes come from a numeric range (or a "c" marker meaning
//! "continue only if payload remains").

use md5::{Digest, Md5};
use rand::Rng;
use std::collections::HashMap;

/// Sentinel value returned for the "c" (check) marker in a padding scheme.
/// Semantics match mihomo's CheckMark constant.
pub const CHECK_MARK: i32 = -1;

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
    /// Raw scheme bytes, kept around so server-pushed updates can
    /// roundtrip it back to peers (matches mihomo).
    #[allow(dead_code)]
    pub raw_scheme: Vec<u8>,
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
        let md5_hex = format!("{:x}", Md5::digest(raw_scheme));
        Some(Self {
            raw_scheme: raw_scheme.to_vec(),
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
}
