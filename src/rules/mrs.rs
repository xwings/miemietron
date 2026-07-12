//! MRS rule-provider format reader.
//!
//! mihomo's MRS files are a zstd stream containing (`rules/provider/mrs_reader.go`):
//! magic `MRS\x01`, one behavior byte (0=domain, 1=ipcidr, 2=classical), an
//! int64 BE rule count, an int64 BE "extra" length (+ payload, reserved), then
//! the behavior strategy's binary body. For `domain` behavior the body is the
//! succinct-trie `DomainSet` serialization (`component/trie/domain_set_bin.go`).
//!
//! miemietron does not port the succinct-trie *matcher*; instead it enumerates
//! every stored pattern once at load time (the `keys()` traversal from
//! `component/trie/domain_set.go`) and feeds the resulting `+.example.com` /
//! `example.com` pattern strings through the same domain-behavior ingestion
//! used for yaml/text providers. Matching semantics therefore stay in one
//! place. Only `domain` behavior is implemented; `ipcidr` MRS files error.

use anyhow::{bail, Context, Result};
use std::io::Read;

/// mihomo compat: `MrsMagicBytes = [4]byte{'M', 'R', 'S', 1}` (MRSv1).
const MRS_MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];

/// Behavior byte values, mihomo `constant/provider/interface.go` Byte().
pub const BEHAVIOR_DOMAIN: u8 = 0;

/// Parse an MRS file (zstd-compressed) into its stored domain pattern strings.
///
/// `expected_behavior` is the provider's configured behavior byte; mihomo
/// errors with "invalid behavior" when the file's byte differs
/// (`mrs_reader.go:40`).
pub fn parse_mrs_domains(compressed: &[u8], expected_behavior: u8) -> Result<Vec<String>> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(compressed))
        .map_err(|e| anyhow::anyhow!("MRS zstd decode error: {e}"))?;
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("MRS zstd decode error: {e}"))?;

    let mut cur = Cursor { buf: &buf, pos: 0 };

    // header
    if cur.take(4)? != MRS_MAGIC {
        bail!("invalid MrsMagic bytes");
    }

    // behavior
    let behavior = cur.take(1)?[0];
    if behavior != expected_behavior {
        bail!("invalid behavior");
    }
    if behavior != BEHAVIOR_DOMAIN {
        bail!("MRS behavior {behavior} not supported (only domain)");
    }

    // count
    let count = cur.read_i64()?;

    // extra (reserved for future using)
    let extra_len = cur.read_i64()?;
    if extra_len < 0 {
        bail!("length is invalid");
    }
    cur.take(extra_len as usize)?;

    let set = read_domain_set_bin(&mut cur)?;
    let domains = set.enumerate();
    if domains.len() as i64 != count {
        tracing::debug!(
            "MRS domain count mismatch: header says {}, enumerated {}",
            count,
            domains.len()
        );
    }
    Ok(domains)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            bail!("MRS payload truncated");
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_i64(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        Ok(i64::from_be_bytes(b.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }
}

/// Succinct-trie domain set, mihomo `component/trie/domain_set.go`. Keys are
/// stored byte-reversed so shared suffixes become shared prefixes.
struct DomainSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// ranks[i] = number of set bits in label_bitmap words [0, i).
    ranks: Vec<u64>,
}

/// mihomo compat: `trie.ReadDomainSetBin` (`domain_set_bin.go:53`).
fn read_domain_set_bin(cur: &mut Cursor) -> Result<DomainSet> {
    let version = cur.take(1).context("DomainSet version")?[0];
    if version != 1 {
        bail!("version is invalid");
    }

    let read_u64_vec = |cur: &mut Cursor| -> Result<Vec<u64>> {
        let len = cur.read_i64()?;
        if len < 1 {
            bail!("length is invalid");
        }
        let mut v = Vec::with_capacity(len as usize);
        for _ in 0..len {
            v.push(cur.read_u64()?);
        }
        Ok(v)
    };

    let leaves = read_u64_vec(cur)?;
    let label_bitmap = read_u64_vec(cur)?;

    let labels_len = cur.read_i64()?;
    if labels_len < 1 {
        bail!("length is invalid");
    }
    let labels = cur.take(labels_len as usize)?.to_vec();

    // rank index over label_bitmap for O(1) rank queries during traversal.
    let mut ranks = Vec::with_capacity(label_bitmap.len() + 1);
    let mut acc = 0u64;
    ranks.push(0);
    for w in &label_bitmap {
        acc += w.count_ones() as u64;
        ranks.push(acc);
    }

    Ok(DomainSet {
        leaves,
        label_bitmap,
        labels,
        ranks,
    })
}

/// Bounds-safe bit test: mihomo's builder only appends leaf words up to the
/// last SET bit, so `leaves` can be shorter than the node count. Out-of-range
/// reads mean "bit not set". Also guards against malformed files — the release
/// profile is `panic = "abort"`, so an index panic here would kill the daemon.
fn get_bit(bm: &[u64], i: usize) -> bool {
    bm.get(i >> 6).is_some_and(|w| w & (1u64 << (i & 63)) != 0)
}

impl DomainSet {
    /// Number of set bits in label_bitmap before index `i` (excluding `i`).
    fn rank1(&self, i: usize) -> u64 {
        let word = i >> 6;
        let mut r = self.ranks[word];
        let rem = i & 63;
        if rem > 0 {
            r += (self.label_bitmap[word] & ((1u64 << rem) - 1)).count_ones() as u64;
        }
        r
    }

    /// mihomo compat: `countZeros(bm, ranks, i)` — zeros before the i-th bit.
    fn count_zeros(&self, i: usize) -> usize {
        i - self.rank1(i) as usize
    }

    /// mihomo compat: `selectIthOne(bm, ranks, selects, i)` — index of the
    /// i-th (0-based) set bit. Binary-search the rank index, then scan the word.
    fn select_ith_one(&self, i: usize) -> usize {
        let target = i as u64;
        // Find the word containing the (target+1)-th set bit.
        let mut lo = 0usize;
        let mut hi = self.label_bitmap.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.ranks[mid + 1] > target {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        let word = lo;
        let mut remaining = target - self.ranks[word];
        let mut w = self.label_bitmap[word];
        loop {
            let tz = w.trailing_zeros() as usize;
            if remaining == 0 {
                return (word << 6) + tz;
            }
            remaining -= 1;
            w &= w - 1;
        }
    }

    /// mihomo compat: `keys()` traversal (`domain_set.go:139`) — enumerate all
    /// stored keys (reversed), then un-reverse like `Foreach`.
    fn enumerate(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        self.traverse(0, 0, &mut current, &mut out);
        out
    }

    fn traverse(
        &self,
        node_id: usize,
        mut bm_idx: usize,
        current: &mut Vec<u8>,
        out: &mut Vec<String>,
    ) {
        if get_bit(&self.leaves, node_id) {
            let reversed: Vec<u8> = current.iter().rev().copied().collect();
            match String::from_utf8(reversed) {
                Ok(s) => out.push(s),
                Err(_) => tracing::debug!("MRS domain entry is not valid UTF-8, skipped"),
            }
        }

        loop {
            if bm_idx >= self.label_bitmap.len() * 64 || get_bit(&self.label_bitmap, bm_idx) {
                return;
            }
            let Some(&next_label) = self.labels.get(bm_idx - node_id) else {
                return;
            };
            current.push(next_label);
            let next_node_id = self.count_zeros(bm_idx + 1);
            let next_bm_idx = self.select_ith_one(next_node_id - 1) + 1;
            self.traverse(next_node_id, next_bm_idx, current, out);
            current.pop();
            bm_idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only port of mihomo's `DomainTrie.NewDomainSet()` succinct-trie
    /// builder (`domain_set.go:29`) so the reader can be exercised without
    /// binary fixtures. Takes the pattern strings a DomainTrie would hold.
    fn build_domain_set(patterns: &[&str]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
        let mut keys: Vec<Vec<u8>> = patterns.iter().map(|p| p.bytes().rev().collect()).collect();
        keys.sort();

        let mut leaves: Vec<u64> = Vec::new();
        let mut label_bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();

        fn set_bit(bm: &mut Vec<u64>, i: usize, v: bool) {
            while i >> 6 >= bm.len() {
                bm.push(0);
            }
            if v {
                bm[i >> 6] |= 1u64 << (i & 63);
            }
        }

        let mut l_idx = 0usize;
        // (start, end, col)
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut i = 0;
        while i < queue.len() {
            let (mut s, e, col) = queue[i];
            // mihomo compat: the Go builder only calls setBit for leaf nodes,
            // so the leaves bitmap ends at the last set bit.
            if col == keys[s].len() {
                s += 1;
                set_bit(&mut leaves, i, true);
            }
            let mut j = s;
            while j < e {
                let frm = j;
                while j < e && keys[j][col] == keys[frm][col] {
                    j += 1;
                }
                queue.push((frm, j, col + 1));
                labels.push(keys[frm][col]);
                set_bit(&mut label_bitmap, l_idx, false);
                l_idx += 1;
            }
            set_bit(&mut label_bitmap, l_idx, true);
            l_idx += 1;
            i += 1;
        }

        (leaves, label_bitmap, labels)
    }

    /// Serialize per `WriteBin` (uncompressed body only).
    fn write_domain_set_bin(leaves: &[u64], label_bitmap: &[u64], labels: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend((leaves.len() as i64).to_be_bytes());
        for d in leaves {
            out.extend(d.to_be_bytes());
        }
        out.extend((label_bitmap.len() as i64).to_be_bytes());
        for d in label_bitmap {
            out.extend(d.to_be_bytes());
        }
        out.extend((labels.len() as i64).to_be_bytes());
        out.extend(labels);
        out
    }

    fn roundtrip(patterns: &[&str]) -> Vec<String> {
        let (leaves, label_bitmap, labels) = build_domain_set(patterns);
        let bin = write_domain_set_bin(&leaves, &label_bitmap, &labels);
        let mut cur = Cursor { buf: &bin, pos: 0 };
        let set = read_domain_set_bin(&mut cur).unwrap();
        let mut got = set.enumerate();
        got.sort();
        got
    }

    #[test]
    fn domain_set_roundtrip_plain() {
        let mut want = vec!["baidu.com", "cn", "qq.com"];
        want.sort();
        assert_eq!(roundtrip(&["baidu.com", "cn", "qq.com"]), want);
    }

    #[test]
    fn domain_set_roundtrip_suffix_patterns() {
        // meta-rules-dat geosite lists are mostly "+.example.com" entries.
        let patterns = ["+.baidu.com", "+.qq.com", "weixin.qq.com", "+.cn"];
        let mut want: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(roundtrip(&patterns), want);
    }

    #[test]
    fn domain_set_roundtrip_shared_suffix() {
        // shared suffixes exercise trie branching
        let patterns = [
            "a.example.com",
            "b.example.com",
            "example.com",
            "example.org",
            "+.sub.example.com",
        ];
        let mut want: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(roundtrip(&patterns), want);
    }

    #[test]
    fn mrs_magic_and_behavior_checks() {
        // Not zstd at all
        assert!(parse_mrs_domains(b"not zstd", BEHAVIOR_DOMAIN).is_err());
    }
}
