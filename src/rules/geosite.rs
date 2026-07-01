use std::collections::HashMap;
use std::path::Path;

/// Domain type from GeoSite.dat protobuf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    /// Keyword match -- domain contains this substring.
    Plain = 0,
    /// Regex match -- domain matches this RE2 pattern.
    Regex = 1,
    /// Suffix match -- domain ends with ".value" or equals "value".
    Domain = 2,
    /// Full/exact match -- domain must equal the value exactly.
    Full = 3,
}

/// A single compiled GeoSite matcher. Built once at load from the parsed
/// `(DomainType, value)` tuples so matching is allocation-free per connection.
/// mihomo compat: `component/geodata/router/condition.go` matcherTypeMap ---
/// Plain=Substr, Regex=Regex, Domain=Domain(+.value), Full=Full.
enum SiteMatcher {
    /// Substring keyword.
    Plain(String),
    /// Suffix: equals `value` or ends with `.value`.
    Suffix(String),
    /// Exact match.
    Full(String),
    /// RE2 regex, compiled verbatim (case-sensitive; input is pre-lowercased).
    Regex(regex::Regex),
}

/// GeoSite matcher: loads mihomo's GeoSite.dat (protobuf-encoded) and matches
/// domains against country-code groups.
pub struct GeoSiteMatcher {
    /// country_code (upper-cased) -> list of compiled matchers
    sites: HashMap<String, Vec<SiteMatcher>>,
}

impl GeoSiteMatcher {
    /// Create a new GeoSite matcher, loading GeoSite.dat from `home_dir`.
    pub fn new(home_dir: &Path) -> Self {
        let dat_path = home_dir.join("GeoSite.dat");
        if !dat_path.exists() {
            tracing::debug!(
                "GeoSite.dat not found at {}, GEOSITE rules will not match",
                dat_path.display()
            );
            return Self {
                sites: HashMap::new(),
            };
        }

        match std::fs::read(&dat_path) {
            Ok(data) => {
                let sites = compile_sites(parse_geosite_dat(&data));
                tracing::info!(
                    "GeoSite.dat loaded: {} site groups from {}",
                    sites.len(),
                    dat_path.display()
                );
                Self { sites }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read GeoSite.dat at {}: {}",
                    dat_path.display(),
                    e
                );
                Self {
                    sites: HashMap::new(),
                }
            }
        }
    }

    /// Check if `domain` belongs to the site group identified by `code`
    /// (e.g. "google", "cn", "category-ads-all").
    pub fn lookup(&self, domain: &str, code: &str) -> bool {
        let code_upper = code.to_uppercase();
        let Some(entries) = self.sites.get(&code_upper) else {
            return false;
        };

        let domain_lower = domain.to_lowercase();
        for matcher in entries {
            match matcher {
                SiteMatcher::Plain(value) => {
                    // Keyword: domain contains the value as a substring.
                    if domain_lower.contains(value) {
                        return true;
                    }
                }
                SiteMatcher::Suffix(value) => {
                    // Suffix: domain ends with ".value" or equals "value".
                    if domain_lower == *value || domain_lower.ends_with(&format!(".{value}")) {
                        return true;
                    }
                }
                SiteMatcher::Full(value) => {
                    // Exact match.
                    if domain_lower == *value {
                        return true;
                    }
                }
                SiteMatcher::Regex(re) => {
                    // RE2 unanchored match against the lowercased domain.
                    if re.is_match(&domain_lower) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Whether any site data was loaded.
    pub fn is_loaded(&self) -> bool {
        !self.sites.is_empty()
    }

    /// Get the number of domain entries for a specific country/group code.
    /// mihomo compat: matches GEOSITE.GetRecodeSize() via matcher.Count().
    pub fn record_count(&self, code: &str) -> usize {
        let code_upper = code.to_uppercase();
        self.sites.get(&code_upper).map(|v| v.len()).unwrap_or(0)
    }
}

//
// Protobuf wire format basics:
//   - Each field is encoded as: tag (varint) + value
//   - tag = (field_number << 3) | wire_type
//   - wire_type 0 = varint
//   - wire_type 2 = length-delimited (string, bytes, embedded message)
//
// GeoSite.dat structure:
//   GeoSiteList { repeated GeoSite entry = 1; }
//   GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//   Domain      { Type type = 1; string value = 2; }
//   Domain.Type { Plain=0, Regex=1, Domain=2, Full=3 }

/// Parse a varint from the buffer, returning (value, bytes_consumed).
/// Returns `None` if the buffer is too short or the varint is malformed.
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None; // overflow
        }
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None // ran out of bytes
}

/// Decode a field tag, returning (field_number, wire_type, bytes_consumed).
fn decode_tag(buf: &[u8]) -> Option<(u32, u8, usize)> {
    let (val, consumed) = decode_varint(buf)?;
    let wire_type = (val & 0x07) as u8;
    let field_number = (val >> 3) as u32;
    Some((field_number, wire_type, consumed))
}

/// Skip a field value based on its wire type. Returns bytes consumed, or None
/// if the data is malformed.
fn skip_field(wire_type: u8, buf: &[u8]) -> Option<usize> {
    match wire_type {
        0 => {
            // varint
            let (_, consumed) = decode_varint(buf)?;
            Some(consumed)
        }
        1 => {
            // 64-bit
            if buf.len() >= 8 {
                Some(8)
            } else {
                None
            }
        }
        2 => {
            // length-delimited
            let (len, hdr) = decode_varint(buf)?;
            let total = hdr + len as usize;
            if buf.len() >= total {
                Some(total)
            } else {
                None
            }
        }
        5 => {
            // 32-bit
            if buf.len() >= 4 {
                Some(4)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse a single Domain message, returning (DomainType, value).
fn parse_domain_msg(buf: &[u8]) -> Option<(DomainType, String)> {
    let mut pos = 0;
    let mut dtype = DomainType::Plain; // default = 0
    let mut value = String::new();

    while pos < buf.len() {
        let (field_num, wire_type, tag_len) = decode_tag(&buf[pos..])?;
        pos += tag_len;

        match (field_num, wire_type) {
            (1, 0) => {
                // type = varint
                let (v, consumed) = decode_varint(&buf[pos..])?;
                pos += consumed;
                dtype = match v {
                    0 => DomainType::Plain,
                    1 => DomainType::Regex,
                    2 => DomainType::Domain,
                    3 => DomainType::Full,
                    _ => DomainType::Plain,
                };
            }
            (2, 2) => {
                // value = string (length-delimited)
                let (len, hdr) = decode_varint(&buf[pos..])?;
                pos += hdr;
                let end = pos + len as usize;
                if end > buf.len() {
                    return None;
                }
                value = String::from_utf8_lossy(&buf[pos..end]).to_lowercase();
                pos = end;
            }
            _ => {
                // Skip unknown fields (attribute list field=3, etc.)
                let skipped = skip_field(wire_type, &buf[pos..])?;
                pos += skipped;
            }
        }
    }

    Some((dtype, value))
}

/// Parse a single GeoSite message, returning (country_code, domains).
fn parse_geosite_msg(buf: &[u8]) -> Option<(String, Vec<(DomainType, String)>)> {
    let mut pos = 0;
    let mut country_code = String::new();
    let mut domains = Vec::new();

    while pos < buf.len() {
        let (field_num, wire_type, tag_len) = decode_tag(&buf[pos..])?;
        pos += tag_len;

        match (field_num, wire_type) {
            (1, 2) => {
                // country_code = string
                let (len, hdr) = decode_varint(&buf[pos..])?;
                pos += hdr;
                let end = pos + len as usize;
                if end > buf.len() {
                    return None;
                }
                country_code = String::from_utf8_lossy(&buf[pos..end]).to_uppercase();
                pos = end;
            }
            (2, 2) => {
                // domain = embedded message
                let (len, hdr) = decode_varint(&buf[pos..])?;
                pos += hdr;
                let end = pos + len as usize;
                if end > buf.len() {
                    return None;
                }
                if let Some(entry) = parse_domain_msg(&buf[pos..end]) {
                    domains.push(entry);
                }
                pos = end;
            }
            _ => {
                let skipped = skip_field(wire_type, &buf[pos..])?;
                pos += skipped;
            }
        }
    }

    if country_code.is_empty() {
        return None;
    }
    Some((country_code, domains))
}

/// Parse an entire GeoSite.dat file (GeoSiteList protobuf).
///
/// Returns a map of uppercase country_code -> list of (DomainType, value).
fn parse_geosite_dat(data: &[u8]) -> HashMap<String, Vec<(DomainType, String)>> {
    let mut result: HashMap<String, Vec<(DomainType, String)>> = HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        let Some((field_num, wire_type, tag_len)) = decode_tag(&data[pos..]) else {
            break;
        };
        pos += tag_len;

        if field_num == 1 && wire_type == 2 {
            // GeoSiteList.entry (field 1, length-delimited = embedded message)
            let Some((len, hdr)) = decode_varint(&data[pos..]) else {
                break;
            };
            pos += hdr;
            let end = pos + len as usize;
            if end > data.len() {
                break;
            }
            if let Some((code, domains)) = parse_geosite_msg(&data[pos..end]) {
                result.entry(code).or_default().extend(domains);
            }
            pos = end;
        } else {
            // Unknown top-level field, skip it.
            let Some(skipped) = skip_field(wire_type, &data[pos..]) else {
                break;
            };
            pos += skipped;
        }
    }

    result
}

/// Compile parsed `(DomainType, value)` tuples into ready-to-match
/// [`SiteMatcher`]s, one map preserving per-category order.
///
/// mihomo compat: a regex that fails to compile aborts config load upstream
/// (`NewSuccinctMatcherGroup` returns the error). We instead `warn!` and skip
/// just that one entry so a single malformed pattern in a huge DB can't take
/// down the whole router; every other entry still matches the DB verbatim.
fn compile_sites(
    parsed: HashMap<String, Vec<(DomainType, String)>>,
) -> HashMap<String, Vec<SiteMatcher>> {
    let mut out: HashMap<String, Vec<SiteMatcher>> = HashMap::with_capacity(parsed.len());
    for (code, entries) in parsed {
        let mut matchers = Vec::with_capacity(entries.len());
        for (dtype, value) in entries {
            match dtype {
                DomainType::Plain => matchers.push(SiteMatcher::Plain(value)),
                DomainType::Domain => matchers.push(SiteMatcher::Suffix(value)),
                DomainType::Full => matchers.push(SiteMatcher::Full(value)),
                DomainType::Regex => match regex::Regex::new(&value) {
                    Ok(re) => matchers.push(SiteMatcher::Regex(re)),
                    Err(e) => {
                        tracing::warn!(
                            "GeoSite regex in category {} failed to compile ({}): {}",
                            code,
                            value,
                            e
                        );
                    }
                },
            }
        }
        out.insert(code, matchers);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a matcher directly from parsed tuples (mirrors `new`'s compile
    /// step) so tests don't need a GeoSite.dat file on disk.
    fn matcher_from(sites: HashMap<String, Vec<(DomainType, String)>>) -> GeoSiteMatcher {
        GeoSiteMatcher {
            sites: compile_sites(sites),
        }
    }

    #[test]
    fn decode_varint_single_byte() {
        assert_eq!(decode_varint(&[0x08]), Some((8, 1)));
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn decode_varint_multi_byte() {
        // 300 = 0b100101100 -> 0xAC 0x02
        assert_eq!(decode_varint(&[0xAC, 0x02]), Some((300, 2)));
    }

    #[test]
    fn decode_tag_basic() {
        // field=1, wire_type=2 (length-delimited) -> tag = (1<<3)|2 = 0x0A
        assert_eq!(decode_tag(&[0x0A]), Some((1, 2, 1)));
        // field=1, wire_type=0 (varint) -> tag = (1<<3)|0 = 0x08
        assert_eq!(decode_tag(&[0x08]), Some((1, 0, 1)));
        // field=2, wire_type=2 -> tag = (2<<3)|2 = 0x12
        assert_eq!(decode_tag(&[0x12]), Some((2, 2, 1)));
    }

    /// Build a minimal protobuf Domain message by hand.
    fn encode_domain(dtype: u8, value: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // field 1 (type), wire_type 0 (varint)
        if dtype != 0 {
            buf.push(0x08); // tag: field=1, wire=0
            buf.push(dtype);
        }
        // field 2 (value), wire_type 2 (length-delimited)
        buf.push(0x12); // tag: field=2, wire=2
        let vb = value.as_bytes();
        // Simple varint for lengths < 128
        buf.push(vb.len() as u8);
        buf.extend_from_slice(vb);
        buf
    }

    /// Build a minimal GeoSite message.
    fn encode_geosite(code: &str, domains: &[(u8, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        // field 1 = country_code (string)
        buf.push(0x0A); // tag: field=1, wire=2
        let cb = code.as_bytes();
        buf.push(cb.len() as u8);
        buf.extend_from_slice(cb);
        // field 2 = repeated Domain (embedded message)
        for &(dtype, val) in domains {
            let dmsg = encode_domain(dtype, val);
            buf.push(0x12); // tag: field=2, wire=2
            buf.push(dmsg.len() as u8);
            buf.extend_from_slice(&dmsg);
        }
        buf
    }

    /// Build a minimal GeoSiteList message.
    fn encode_geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in entries {
            buf.push(0x0A); // tag: field=1, wire=2
                            // encode length as varint
            let len = entry.len();
            if len < 128 {
                buf.push(len as u8);
            } else {
                buf.push((len as u8 & 0x7F) | 0x80);
                buf.push((len >> 7) as u8);
            }
            buf.extend_from_slice(entry);
        }
        buf
    }

    #[test]
    fn parse_domain_msg_plain() {
        let data = encode_domain(0, "google");
        let (dtype, val) = parse_domain_msg(&data).unwrap();
        assert_eq!(dtype, DomainType::Plain);
        assert_eq!(val, "google");
    }

    #[test]
    fn parse_domain_msg_full() {
        let data = encode_domain(3, "www.google.com");
        let (dtype, val) = parse_domain_msg(&data).unwrap();
        assert_eq!(dtype, DomainType::Full);
        assert_eq!(val, "www.google.com");
    }

    #[test]
    fn parse_geosite_msg_basic() {
        let data = encode_geosite(
            "GOOGLE",
            &[(0, "google"), (2, "google.com"), (3, "www.google.com")],
        );
        let (code, domains) = parse_geosite_msg(&data).unwrap();
        assert_eq!(code, "GOOGLE");
        assert_eq!(domains.len(), 3);
        assert_eq!(domains[0], (DomainType::Plain, "google".to_string()));
        assert_eq!(domains[1], (DomainType::Domain, "google.com".to_string()));
        assert_eq!(domains[2], (DomainType::Full, "www.google.com".to_string()));
    }

    #[test]
    fn parse_geosite_dat_roundtrip() {
        let gs1 = encode_geosite("GOOGLE", &[(0, "google"), (2, "google.com")]);
        let gs2 = encode_geosite("CN", &[(2, "baidu.com"), (3, "www.qq.com")]);
        let dat = encode_geosite_list(&[gs1, gs2]);

        let map = parse_geosite_dat(&dat);
        assert_eq!(map.len(), 2);

        let google = map.get("GOOGLE").unwrap();
        assert_eq!(google.len(), 2);
        assert_eq!(google[0], (DomainType::Plain, "google".to_string()));
        assert_eq!(google[1], (DomainType::Domain, "google.com".to_string()));

        let cn = map.get("CN").unwrap();
        assert_eq!(cn.len(), 2);
        assert_eq!(cn[0], (DomainType::Domain, "baidu.com".to_string()));
        assert_eq!(cn[1], (DomainType::Full, "www.qq.com".to_string()));
    }

    #[test]
    fn regex_entries_are_kept() {
        // mihomo treats regex domains as authoritative; they must survive parse.
        let gs = encode_geosite("TEST", &[(1, "^regex.*pattern$"), (2, "example.com")]);
        let dat = encode_geosite_list(&[gs]);
        let map = parse_geosite_dat(&dat);
        let entries = map.get("TEST").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (DomainType::Regex, "^regex.*pattern$".to_string()));
        assert_eq!(entries[1], (DomainType::Domain, "example.com".to_string()));
    }

    #[test]
    fn lookup_keyword_match() {
        let gs = encode_geosite("GOOGLE", &[(0, "google")]);
        let dat = encode_geosite_list(&[gs]);
        let matcher = matcher_from(parse_geosite_dat(&dat));

        assert!(matcher.lookup("www.google.com", "google"));
        assert!(matcher.lookup("mail.google.co.jp", "google"));
        assert!(!matcher.lookup("www.example.com", "google"));
    }

    #[test]
    fn lookup_suffix_match() {
        let gs = encode_geosite("CN", &[(2, "baidu.com")]);
        let dat = encode_geosite_list(&[gs]);
        let matcher = matcher_from(parse_geosite_dat(&dat));

        assert!(matcher.lookup("baidu.com", "cn"));
        assert!(matcher.lookup("www.baidu.com", "cn"));
        assert!(matcher.lookup("tieba.baidu.com", "cn"));
        assert!(!matcher.lookup("notbaidu.com", "cn"));
    }

    #[test]
    fn lookup_full_match() {
        let gs = encode_geosite("TEST", &[(3, "exact.example.com")]);
        let dat = encode_geosite_list(&[gs]);
        let matcher = matcher_from(parse_geosite_dat(&dat));

        assert!(matcher.lookup("exact.example.com", "test"));
        assert!(!matcher.lookup("sub.exact.example.com", "test"));
        assert!(!matcher.lookup("example.com", "test"));
    }

    #[test]
    fn lookup_unknown_code_returns_false() {
        let matcher = GeoSiteMatcher {
            sites: HashMap::new(),
        };
        assert!(!matcher.lookup("anything.com", "nonexistent"));
    }

    #[test]
    fn lookup_regex_match() {
        // A category whose only way to match some hosts is a regex entry.
        let gs = encode_geosite("ADS", &[(2, "example.com"), (1, r".*\.ads\..*")]);
        let dat = encode_geosite_list(&[gs]);
        let matcher = matcher_from(parse_geosite_dat(&dat));

        // Matches via the regex entry only.
        assert!(matcher.lookup("tracker.ads.net", "ads"));
        // Matches via the suffix entry.
        assert!(matcher.lookup("www.example.com", "ads"));
        // Matches neither.
        assert!(!matcher.lookup("clean.example.org", "ads"));
    }

    #[test]
    fn lookup_regex_is_case_insensitive_on_input() {
        // mihomo lowercases the domain before matching; the regex itself is
        // compiled verbatim, so a lowercase pattern still matches mixed-case
        // input via the pre-lowering in `lookup`.
        let gs = encode_geosite("RE", &[(1, r"^cdn[0-9]+\.example\.com$")]);
        let dat = encode_geosite_list(&[gs]);
        let matcher = matcher_from(parse_geosite_dat(&dat));

        assert!(matcher.lookup("CDN42.Example.Com", "re"));
        assert!(!matcher.lookup("cdn.example.com", "re"));
    }

    #[test]
    fn empty_dat_file() {
        let map = parse_geosite_dat(&[]);
        assert!(map.is_empty());
    }
}
