// Protocol sniffers for HTTP, TLS, and QUIC.

mod http;
pub mod quic;

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
/// Tries TLS SNI first (if the data starts with 0x16), then HTTP Host.
/// QUIC uses a stateful UDP sniffer in `quic`.
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

    if data[0] == 0x16 {
        return sniff_tls(data);
    }

    http::sniff_http(data)
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

#[cfg(test)]
fn extract_http_host(data: &[u8]) -> Option<String> {
    match http::sniff_http(data) {
        SniffAttempt::Found(host) => Some(host),
        _ => None,
    }
}

pub(super) fn sniff_tls(data: &[u8]) -> SniffAttempt {
    let mut offset = 0;
    let mut hello = Vec::new();
    loop {
        if data.len() < offset + 5 {
            return SniffAttempt::NeedMore(offset + 5);
        }
        if data[offset] != 0x16 || data[offset + 1] != 3 {
            return SniffAttempt::Fail;
        }
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if length == 0 || length > 16384 || hello.len() + length > 64 * 1024 {
            return SniffAttempt::Fail;
        }
        let end = offset + 5 + length;
        let previous = hello.len();
        hello.extend_from_slice(&data[offset + 5..end.min(data.len())]);
        match read_client_hello(&hello) {
            SniffAttempt::NeedMore(want) if data.len() < end => {
                return SniffAttempt::NeedMore(offset + 5 + (want - previous).min(length));
            }
            SniffAttempt::NeedMore(_) => offset = end,
            result => return result,
        }
    }
}

#[cfg(test)]
fn extract_tls_sni(data: &[u8]) -> Option<String> {
    match sniff_tls(data) {
        SniffAttempt::Found(host) => Some(host),
        _ => None,
    }
}

/// Shared TLS/QUIC ClientHello parser. A complete server_name field is enough;
/// trailing padding need not arrive. All lengths remain inside the declared
/// handshake, extensions, and name-list boundaries.
fn read_client_hello(data: &[u8]) -> SniffAttempt {
    fn parse(data: &[u8]) -> Result<String, SniffAttempt> {
        if data.is_empty() {
            return Err(SniffAttempt::NeedMore(1));
        }
        if data[0] != 1 {
            return Err(SniffAttempt::Fail);
        }
        if data.len() < 4 {
            return Err(SniffAttempt::NeedMore(4));
        }
        let total =
            4 + ((usize::from(data[1]) << 16) | (usize::from(data[2]) << 8) | usize::from(data[3]));
        let need = |end| {
            if end > total {
                Err(SniffAttempt::Fail)
            } else if end > data.len() {
                Err(SniffAttempt::NeedMore(end))
            } else {
                Ok(())
            }
        };
        let u16_at = |pos| u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        let mut pos = 38; // handshake header, legacy_version, random
        need(pos + 1)?;
        let session = usize::from(data[pos]);
        if session > 32 {
            return Err(SniffAttempt::Fail);
        }
        pos += 1 + session;
        need(pos + 2)?;
        let ciphers = u16_at(pos);
        if ciphers % 2 != 0 {
            return Err(SniffAttempt::Fail);
        }
        pos += 2 + ciphers;
        need(pos + 1)?;
        let compression = usize::from(data[pos]);
        pos += 1 + compression;
        need(pos + 2)?;
        let extensions_end = pos + 2 + u16_at(pos);
        if extensions_end != total {
            return Err(SniffAttempt::Fail);
        }
        pos += 2;
        while pos < extensions_end {
            need(pos + 4)?;
            let kind = u16_at(pos);
            let extension_end = pos + 4 + u16_at(pos + 2);
            if extension_end > extensions_end {
                return Err(SniffAttempt::Fail);
            }
            pos += 4;
            if kind != 0 {
                if extension_end == extensions_end {
                    return Err(SniffAttempt::Fail);
                }
                need(extension_end)?;
                pos = extension_end;
                continue;
            }
            if pos + 2 > extension_end {
                return Err(SniffAttempt::Fail);
            }
            need(pos + 2)?;
            let names_end = pos + 2 + u16_at(pos);
            if names_end != extension_end {
                return Err(SniffAttempt::Fail);
            }
            pos += 2;
            while pos < names_end {
                if pos + 3 > names_end {
                    return Err(SniffAttempt::Fail);
                }
                need(pos + 3)?;
                let name_type = data[pos];
                let name_end = pos + 3 + u16_at(pos + 1);
                if name_end > names_end {
                    return Err(SniffAttempt::Fail);
                }
                pos += 3;
                need(name_end)?;
                if name_type == 0 {
                    let name = std::str::from_utf8(&data[pos..name_end])
                        .map_err(|_| SniffAttempt::Fail)?;
                    if name.ends_with('.') {
                        return Err(SniffAttempt::Fail);
                    }
                    return Ok(name.to_string());
                }
                pos = name_end;
            }
        }
        Err(SniffAttempt::Fail)
    }
    match parse(data) {
        Ok(host) => SniffAttempt::Found(host),
        Err(verdict) => verdict,
    }
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
    pub(super) fn build_client_hello(sni: &str) -> Vec<u8> {
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
    fn tls_client_hello_across_records_and_partial_reads() {
        let original = build_client_hello("fragmented.example.com");
        let hello = &original[5..];
        let mut wire = Vec::new();
        for part in hello.chunks(17) {
            wire.extend_from_slice(&[0x16, 3, 3]);
            wire.extend_from_slice(&(part.len() as u16).to_be_bytes());
            wire.extend_from_slice(part);
        }
        for n in 0..wire.len() {
            assert!(matches!(sniff_tls(&wire[..n]), SniffAttempt::NeedMore(want) if want > n));
        }
        assert_eq!(
            extract_tls_sni(&wire).as_deref(),
            Some("fragmented.example.com")
        );
    }

    #[test]
    fn client_hello_prefix_recovers_sni_before_trailing_padding() {
        let packet = build_client_hello("prefix.example.com");
        let mut hello = packet[5..].to_vec();
        let old_len = hello.len();
        let padding = 20000;
        let length = hello.len() + 4 + padding - 4;
        hello[1..4].copy_from_slice(&(length as u32).to_be_bytes()[1..]);
        // Existing minimal fixture has the extension length at offset 45.
        let extensions = u16::from_be_bytes([hello[45], hello[46]]) + 4 + padding as u16;
        hello[45..47].copy_from_slice(&extensions.to_be_bytes());
        hello.extend_from_slice(&[0, 0x15]);
        hello.extend_from_slice(&(padding as u16).to_be_bytes());
        hello.resize(hello.len() + padding, 0);
        assert!(
            matches!(read_client_hello(&hello[..old_len]), SniffAttempt::Found(host) if host == "prefix.example.com")
        );

        // A name cannot escape its own extension/list by using trailing bytes.
        let mut malformed = packet[5..].to_vec();
        malformed[54..56].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(read_client_hello(&malformed), SniffAttempt::Fail));
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
