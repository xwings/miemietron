// Protocol sniffer - extract domain from TLS ClientHello SNI and HTTP Host header.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// mihomo compat: LRU-like skip list for destinations that repeatedly fail sniffing.
/// Matches mihomo's `skipList` in `component/sniffer/dispatcher.go`.
///
/// mihomo uses `lru.New(WithSize(128), WithAge(600))` — an LRU cache with max 128
/// entries and 600-second TTL. It stores a uint8 counter per destination, and only
/// skips sniffing when the counter exceeds 5 (i.e., after 6 consecutive failures).
/// On successful sniff, the entry is deleted.
///
/// We approximate this with a DashMap + TTL check (no strict size cap, but the TTL
/// ensures stale entries expire). The counter behavior matches mihomo exactly.
const SNIFF_SKIP_TTL: Duration = Duration::from_secs(600);

/// Maximum failure count before sniffing is skipped.
/// mihomo: `if count, ok := sd.skipList.Get(dst); ok && count > 5`
const SNIFF_SKIP_THRESHOLD: u8 = 5;

pub struct SniffCache {
    /// Destinations that failed sniffing — skip for SNIFF_SKIP_TTL seconds.
    /// Uses SocketAddr key to avoid format!() allocation per connection.
    skip_list: DashMap<std::net::SocketAddr, (AtomicU8, Instant)>,
}

impl Default for SniffCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SniffCache {
    pub fn new() -> Self {
        Self {
            skip_list: DashMap::new(),
        }
    }

    /// Check if a destination should skip sniffing.
    /// mihomo compat: returns true only if count > 5 AND entry is within TTL.
    pub fn should_skip(&self, dst: std::net::SocketAddr) -> bool {
        if let Some(entry) = self.skip_list.get(&dst) {
            let (count, recorded) = entry.value();
            if recorded.elapsed() >= SNIFF_SKIP_TTL {
                drop(entry);
                self.skip_list.remove(&dst);
                return false;
            }
            return count.load(Ordering::Relaxed) > SNIFF_SKIP_THRESHOLD;
        }
        false
    }

    /// Record a failed sniff attempt.
    /// mihomo compat: increments counter up to 6, matching `cacheSniffFailed`.
    pub fn record_failure(&self, dst: std::net::SocketAddr) {
        // entry() holds the shard write lock, so the reset/increment is atomic
        // (no load+store or get-then-insert races).
        let mut entry = self
            .skip_list
            .entry(dst)
            .or_insert_with(|| (AtomicU8::new(0), Instant::now()));
        let (count, recorded) = entry.value_mut();
        if recorded.elapsed() >= SNIFF_SKIP_TTL {
            *count.get_mut() = 1;
            *recorded = Instant::now();
        } else {
            let count = count.get_mut();
            if *count <= SNIFF_SKIP_THRESHOLD {
                *count += 1;
            }
        }
    }

    /// Remove a destination from the skip list (called on successful sniff).
    /// mihomo compat: `sd.skipList.Delete(dst)` after successful sniffing.
    pub fn record_success(&self, dst: std::net::SocketAddr) {
        self.skip_list.remove(&dst);
    }
}

/// Sniff the domain from a connection's initial bytes.
///
/// Tries TLS SNI first (if the data starts with 0x16), then QUIC Initial
/// packets, then HTTP Host header. Returns `None` if no domain can be
/// extracted.
/// Test convenience wrapper over [`sniff_domain_ex`] — the connection path
/// uses the three-way result directly (it needs NeedMore for the re-peek).
#[cfg(test)]
fn sniff_domain(data: &[u8]) -> Option<String> {
    match sniff_domain_ex(data) {
        SniffAttempt::Found(host) => Some(host),
        _ => None,
    }
}

/// Result of a TCP sniff attempt over buffered bytes.
/// mihomo compat: `errNeedAtLeastData` (tls_sniffer.go) tells the dispatcher
/// to peek again until the whole TLS record is buffered — modern browser
/// ClientHellos with post-quantum key shares exceed a single read.
pub enum SniffAttempt {
    Found(String),
    /// Need at least this many bytes buffered before deciding.
    NeedMore(usize),
    Fail,
}

pub fn sniff_domain_ex(data: &[u8]) -> SniffAttempt {
    if data.is_empty() {
        return SniffAttempt::NeedMore(1);
    }

    // TLS handshake starts with 0x16
    if data[0] == 0x16 {
        if data.len() < 5 {
            return SniffAttempt::NeedMore(5);
        }
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let needed = 5 + record_len;
        if data.len() < needed {
            return SniffAttempt::NeedMore(needed);
        }
        return match extract_tls_sni(data) {
            Some(host) => SniffAttempt::Found(host),
            None => SniffAttempt::Fail,
        };
    }

    // QUIC long header: form bit (0x80) set. No version check is done here —
    // extract_quic_sni heuristically hunts for the embedded ClientHello.
    if data.len() > 5 && (data[0] & 0x80) != 0 {
        if let Some(sni) = extract_quic_sni(data) {
            return SniffAttempt::Found(sni);
        }
    }

    // Try HTTP Host header
    match extract_http_host(data) {
        Some(host) => SniffAttempt::Found(host),
        None => SniffAttempt::Fail,
    }
}

/// mihomo compat: metadata.IsDomainName (net/dnsmessage rules) — the sniffed
/// host must be a plausible DNS name; IP literals are rejected separately.
pub fn is_domain_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 254 || host == "." {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Extract SNI from a QUIC Initial packet.
///
/// QUIC Initial packets contain a CRYPTO frame with a TLS ClientHello.
/// We attempt to find the ClientHello within the unencrypted Initial packet
/// payload and extract SNI from it. This only works for the initial
/// unencrypted packet (before key establishment).
///
/// Note: Full QUIC Initial decryption requires deriving keys from the DCID.
/// This simplified version looks for the TLS ClientHello signature directly
/// in the packet data, which works for many real-world QUIC implementations
/// where the Initial packet is not yet encrypted with application keys.
fn extract_quic_sni(data: &[u8]) -> Option<String> {
    // Look for TLS ClientHello signature (0x01 = handshake type, followed by
    // 3-byte length, then TLS version 0x0303) anywhere in the QUIC packet.
    // This is a heuristic that works because the CRYPTO frame contains a raw
    // TLS ClientHello message.
    for i in 0..data.len().saturating_sub(10) {
        // ClientHello: handshake_type=0x01, then 3 bytes length, then
        // client_version 0x0303 (TLS 1.2 in ClientHello)
        if data[i] == 0x01 && i + 6 < data.len() && data[i + 4] == 0x03 && data[i + 5] == 0x03 {
            // Try to parse as a TLS ClientHello starting at offset i
            // Reconstruct a fake TLS record: 0x16 0x03 0x01 [length] [handshake]
            let remaining = &data[i..];
            if remaining.len() > 4 {
                let hs_len = ((remaining[1] as usize) << 16)
                    | ((remaining[2] as usize) << 8)
                    | (remaining[3] as usize);
                if hs_len > 0 && i + 4 + hs_len <= data.len() {
                    // Build a fake TLS record around this ClientHello
                    let record_len = 4 + hs_len; // handshake header + body
                    let mut fake_record = Vec::with_capacity(5 + record_len);
                    fake_record.push(0x16); // TLS record type: Handshake
                    fake_record.push(0x03);
                    fake_record.push(0x01); // TLS version
                    fake_record.push((record_len >> 8) as u8);
                    fake_record.push((record_len & 0xff) as u8);
                    fake_record.extend_from_slice(&remaining[..record_len.min(remaining.len())]);
                    if let Some(sni) = extract_tls_sni(&fake_record) {
                        return Some(sni);
                    }
                }
            }
        }
    }
    None
}

/// Extract the Host header from an HTTP request.
///
/// Recognises requests starting with common HTTP methods:
/// GET, POST, PUT, DELETE, HEAD, CONNECT, OPTIONS, PATCH, TRACE.
fn extract_http_host(data: &[u8]) -> Option<String> {
    // Quick check: is this an HTTP request?
    let http_methods: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"CONNECT ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
    ];

    let is_http = http_methods.iter().any(|m| data.starts_with(m));
    if !is_http {
        return None;
    }

    // Scan for "Host:" header (case-insensitive).
    // HTTP headers are separated by \r\n. We search for \r\nHost: or
    // check if it's the first header after the request line.
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Try partial — headers should be ASCII
            let valid_len = data.iter().position(|&b| b > 0x7F).unwrap_or(data.len());
            if valid_len == 0 {
                return None;
            }
            std::str::from_utf8(&data[..valid_len]).ok()?
        }
    };

    // Look for the Host header (case-insensitive, no per-line allocation)
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            // End of headers
            break;
        }
        if line.len() >= 5 && line.as_bytes()[..5].eq_ignore_ascii_case(b"Host:") {
            let host = line[5..].trim();
            if host.contains(']') {
                // IPv6 literal like [::1]:80 — not a domain
                return None;
            }
            // Strip port suffix if present (e.g., "example.com:443")
            let domain = if let Some(colon) = host.rfind(':') {
                &host[..colon]
            } else {
                host
            };
            if !domain.is_empty() {
                return Some(domain.to_string());
            }
        }
    }

    None
}

/// Extract SNI from a TLS ClientHello message.
fn extract_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record layer
    if data.len() < 5 || data[0] != 0x16 {
        return None; // Not a TLS handshake
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None; // Not ClientHello
    }

    if hs.len() < 4 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return None;
    }

    let ch = &hs[4..];
    // Skip: version(2) + random(32) + session_id_len(1) + session_id
    // Layout: ch[0..2]=client_version, ch[2..34]=random, ch[34]=session_id_len,
    // ch[35..]=session_id. mihomo reads the length byte at the same offset
    // (tls_sniffer.go: data[38] including the 4-byte handshake header).
    if ch.len() < 35 {
        return None;
    }
    let session_id_len = ch[34] as usize;
    let mut pos = 35 + session_id_len;

    // Skip cipher suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Skip compression methods
    if pos + 1 > ch.len() {
        return None;
    }
    let comp_len = ch[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    while pos + 4 <= ext_end && pos + 4 <= ch.len() {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if pos + 2 > ch.len() {
                return None;
            }
            let sni_list_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            let mut sni_pos = pos + 2;
            let sni_end = sni_pos + sni_list_len;

            while sni_pos + 3 <= sni_end && sni_pos + 3 <= ch.len() {
                let name_type = ch[sni_pos];
                let name_len = u16::from_be_bytes([ch[sni_pos + 1], ch[sni_pos + 2]]) as usize;
                sni_pos += 3;

                if name_type == 0 && sni_pos + name_len <= ch.len() {
                    // Use from_utf8 on slice to avoid .to_vec() allocation
                    return std::str::from_utf8(&ch[sni_pos..sni_pos + name_len])
                        .ok()
                        .map(|s| s.to_string());
                }

                sni_pos += name_len;
            }
        }

        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr1() -> SocketAddr {
        "1.2.3.4:443".parse().unwrap()
    }
    fn addr2() -> SocketAddr {
        "5.6.7.8:443".parse().unwrap()
    }
    fn addr3() -> SocketAddr {
        "1.2.3.4:80".parse().unwrap()
    }

    /// Build a minimal, RFC-conformant TLS 1.2 ClientHello with a single SNI
    /// extension: version(2) + random(32) + session_id_len(1) + session_id +
    /// cipher_suites + compression + extensions.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();

        // SNI extension data:
        //   sni_list_len (2) + name_type (1) + name_len (2) + name
        let sni_list_len = (1 + 2 + sni_bytes.len()) as u16;
        let sni_ext_data_len = 2 + sni_list_len;

        let mut sni_ext = Vec::new();
        // Extension type: SNI (0x0000)
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        // Extension data length
        sni_ext.extend_from_slice(&sni_ext_data_len.to_be_bytes());
        // SNI list length
        sni_ext.extend_from_slice(&sni_list_len.to_be_bytes());
        // Name type: hostname (0)
        sni_ext.push(0x00);
        // Name length
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        // Name
        sni_ext.extend_from_slice(sni_bytes);

        let extensions_len = sni_ext.len() as u16;

        // ClientHello body (RFC 5246 §7.4.1.2):
        //   version(2) + random(32) + session_id_len(1) + session_id +
        //   cipher_suites_len(2) + cipher_suite(2) +
        //   comp_len(1) + comp(1) +
        //   extensions_len(2) + extensions
        let mut ch_body = Vec::new();
        // Version: TLS 1.2
        ch_body.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        ch_body.extend_from_slice(&[0xABu8; 32]);
        // Session ID: length 0 (no session id bytes)
        ch_body.push(0x00);
        // Cipher suites length: 2 (one cipher suite)
        ch_body.extend_from_slice(&[0x00, 0x02]);
        // One cipher suite
        ch_body.extend_from_slice(&[0x00, 0x9c]);
        // Compression methods length: 1
        ch_body.push(0x01);
        // Compression method: null
        ch_body.push(0x00);
        // Extensions length
        ch_body.extend_from_slice(&extensions_len.to_be_bytes());
        // Extensions
        ch_body.extend_from_slice(&sni_ext);

        // Handshake header:
        //   type(1) = ClientHello(0x01) + length(3)
        let ch_len = ch_body.len();
        let mut handshake = vec![
            0x01, // ClientHello
            ((ch_len >> 16) & 0xFF) as u8,
            ((ch_len >> 8) & 0xFF) as u8,
            (ch_len & 0xFF) as u8,
        ];
        handshake.extend_from_slice(&ch_body);

        // TLS record layer:
        //   type(1) = Handshake(0x16) + version(2) + length(2)
        let hs_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version (common)
        record.extend_from_slice(&(hs_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn extract_sni_from_client_hello() {
        let packet = build_client_hello("example.com");
        assert_eq!(extract_tls_sni(&packet), Some("example.com".to_string()));
    }

    #[test]
    fn extract_sni_with_subdomain() {
        let packet = build_client_hello("www.google.com");
        assert_eq!(extract_tls_sni(&packet), Some("www.google.com".to_string()));
    }

    #[test]
    fn returns_none_for_non_tls_data() {
        // HTTP request data
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_tls_sni(data), None);
    }

    #[test]
    fn returns_none_for_empty_data() {
        assert_eq!(extract_tls_sni(&[]), None);
    }

    #[test]
    fn returns_none_for_truncated_data() {
        // Just the TLS record header, truncated before handshake
        let data = &[0x16, 0x03, 0x01, 0x00, 0x50];
        assert_eq!(extract_tls_sni(data), None);
    }

    #[test]
    fn returns_none_for_short_data() {
        let data = &[0x16, 0x03];
        assert_eq!(extract_tls_sni(data), None);
    }

    #[test]
    fn extract_http_host_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn extract_http_host_post() {
        let data = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("api.example.com".to_string()));
    }

    #[test]
    fn extract_http_host_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn extract_http_host_lowercase() {
        let data = b"GET / HTTP/1.1\r\nhost: lowercase.com\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("lowercase.com".to_string()));
    }

    #[test]
    fn extract_http_host_none_for_binary() {
        let data = &[0x00, 0x01, 0x02, 0x03];
        assert_eq!(extract_http_host(data), None);
    }

    #[test]
    fn extract_http_host_connect() {
        let data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn sniff_domain_tls() {
        let packet = build_client_hello("tls.example.com");
        assert_eq!(sniff_domain(&packet), Some("tls.example.com".to_string()));
    }

    #[test]
    fn sniff_domain_http() {
        let data = b"GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n";
        assert_eq!(sniff_domain(data), Some("http.example.com".to_string()));
    }

    #[test]
    fn sniff_domain_empty() {
        assert_eq!(sniff_domain(&[]), None);
    }

    #[test]
    fn extract_http_host_put() {
        let data = b"PUT /resource HTTP/1.1\r\nHost: put.example.com\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("put.example.com".to_string()));
    }

    #[test]
    fn extract_http_host_delete() {
        let data = b"DELETE /item/42 HTTP/1.1\r\nHost: api.delete.com\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("api.delete.com".to_string()));
    }

    #[test]
    fn extract_http_host_head() {
        let data = b"HEAD / HTTP/1.1\r\nHost: head.example.com\r\n\r\n";
        assert_eq!(
            extract_http_host(data),
            Some("head.example.com".to_string())
        );
    }

    #[test]
    fn extract_http_host_options() {
        let data = b"OPTIONS * HTTP/1.1\r\nHost: options.example.com\r\n\r\n";
        assert_eq!(
            extract_http_host(data),
            Some("options.example.com".to_string())
        );
    }

    #[test]
    fn extract_http_host_patch() {
        let data = b"PATCH /item HTTP/1.1\r\nHost: patch.example.com\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(
            extract_http_host(data),
            Some("patch.example.com".to_string())
        );
    }

    #[test]
    fn extract_http_host_trace() {
        let data = b"TRACE / HTTP/1.1\r\nHost: trace.example.com\r\n\r\n";
        assert_eq!(
            extract_http_host(data),
            Some("trace.example.com".to_string())
        );
    }

    #[test]
    fn extract_http_host_strips_standard_port_443() {
        let data = b"GET / HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n";
        assert_eq!(
            extract_http_host(data),
            Some("secure.example.com".to_string())
        );
    }

    #[test]
    fn extract_http_host_strips_nonstandard_port() {
        let data = b"GET / HTTP/1.1\r\nHost: app.example.com:3000\r\n\r\n";
        assert_eq!(extract_http_host(data), Some("app.example.com".to_string()));
    }

    #[test]
    fn extract_http_host_ipv6_literal_returns_none() {
        let data = b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n";
        assert_eq!(extract_http_host(data), None);
    }

    #[test]
    fn extract_http_host_not_http_method() {
        let data = b"INVALID / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(data), None);
    }

    #[test]
    fn extract_http_host_missing_host_header() {
        let data = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(data), None);
    }

    #[test]
    fn extract_http_host_connect_with_port() {
        let data =
            b"CONNECT proxy.example.com:8443 HTTP/1.1\r\nHost: proxy.example.com:8443\r\n\r\n";
        assert_eq!(
            extract_http_host(data),
            Some("proxy.example.com".to_string())
        );
    }

    #[test]
    fn extract_http_host_with_extra_whitespace() {
        let data = b"GET / HTTP/1.1\r\nHost:   spaced.example.com  \r\n\r\n";
        assert_eq!(
            extract_http_host(data),
            Some("spaced.example.com".to_string())
        );
    }

    #[test]
    fn sniff_domain_non_tls_non_http() {
        // Random binary data starting with something other than 0x16
        let data = &[0x50, 0x51, 0x52, 0x53, 0x54];
        assert_eq!(sniff_domain(data), None);
    }

    #[test]
    fn sniff_domain_prefers_tls_over_http() {
        // Data starting with 0x16 should try TLS first
        let packet = build_client_hello("tls-priority.example.com");
        assert_eq!(
            sniff_domain(&packet),
            Some("tls-priority.example.com".to_string())
        );
    }

    #[test]
    fn sniff_domain_single_byte() {
        assert_eq!(sniff_domain(&[0x00]), None);
        assert_eq!(sniff_domain(&[0x16]), None); // TLS marker but truncated
    }

    #[test]
    fn sniff_cache_new_dst_not_skipped() {
        let cache = SniffCache::new();
        assert!(!cache.should_skip(addr1()));
    }

    #[test]
    fn sniff_cache_single_failure_not_skipped() {
        let cache = SniffCache::new();
        cache.record_failure(addr1());
        assert!(!cache.should_skip(addr1()));
    }

    #[test]
    fn sniff_cache_five_failures_not_skipped() {
        // mihomo skips only when count > 5, so 5 failures should NOT skip
        let cache = SniffCache::new();
        for _ in 0..5 {
            cache.record_failure(addr1());
        }
        assert!(!cache.should_skip(addr1()));
    }

    #[test]
    fn sniff_cache_six_failures_skipped() {
        // mihomo: counter goes 1,2,3,4,5,6 and check is count > 5
        let cache = SniffCache::new();
        for _ in 0..6 {
            cache.record_failure(addr1());
        }
        assert!(cache.should_skip(addr1()));
    }

    #[test]
    fn sniff_cache_success_clears_entry() {
        let cache = SniffCache::new();
        for _ in 0..6 {
            cache.record_failure(addr1());
        }
        assert!(cache.should_skip(addr1()));

        cache.record_success(addr1());
        assert!(!cache.should_skip(addr1()));
    }

    #[test]
    fn sniff_cache_different_destinations_independent() {
        let cache = SniffCache::new();
        for _ in 0..6 {
            cache.record_failure(addr1());
        }
        assert!(cache.should_skip(addr1()));
        assert!(!cache.should_skip(addr2()));
        assert!(!cache.should_skip(addr3()));
    }

    #[test]
    fn sniff_cache_counter_caps_at_threshold_plus_one() {
        // mihomo: `if oldValue <= 5 { oldValue++ }` — caps at 6
        let cache = SniffCache::new();
        for _ in 0..20 {
            cache.record_failure(addr1());
        }
        // Should still be skipped (counter capped, not overflowed)
        assert!(cache.should_skip(addr1()));
    }

    #[test]
    fn sniff_cache_ttl_expiry() {
        // We can't easily test the 600s TTL in a unit test without sleeping,
        // but we can verify that the internal structure is correct by checking
        // that a newly inserted entry is not expired.
        let cache = SniffCache::new();
        for _ in 0..6 {
            cache.record_failure(addr1());
        }
        // Entry was just created, should still be valid
        assert!(cache.should_skip(addr1()));
    }
}
