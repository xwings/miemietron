use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::debug;

use crate::config::DnsConfig;
use crate::rules::geoip::GeoIpMatcher;
use crate::transport::tls::{wrap_tls, TlsOptions};

/// Global lazy GeoIP matcher for DNS fallback filtering.
///
/// Loaded once from the home directory on first access. The home dir is resolved
/// using the same logic as `main.rs` (CLASH_HOME_DIR env or ~/.config/mihomo).
static DNS_GEOIP: std::sync::LazyLock<GeoIpMatcher> = std::sync::LazyLock::new(|| {
    let home_dir = if let Ok(dir) = std::env::var("CLASH_HOME_DIR") {
        std::path::PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        std::path::PathBuf::from(home)
            .join(".config")
            .join("mihomo")
    };
    GeoIpMatcher::new(&home_dir)
});

/// Resolve a proxy server hostname using only direct/bootstrap DNS.
///
/// Uses `proxy-server-nameserver` if configured, otherwise falls back to
/// `default-nameserver`. These are typically plain UDP servers (e.g.
/// 114.114.114.114) set by OpenClash, avoiding the circular dependency
/// where DoH/DoT nameservers need a proxy but the proxy needs DNS first.
pub async fn resolve_proxy_server(domain: &str, config: &DnsConfig) -> Result<IpAddr> {
    // 0. Check nameserver-policy first (e.g. "+.oix_nodes.com": "124.221.68.73:1053")
    if let Some(server) = match_nameserver_policy(domain, &config.nameserver_policy) {
        match query_server(domain, &server).await {
            Ok(ip) => {
                debug!(
                    "DNS nameserver-policy resolved {} -> {} via {}",
                    domain, ip, server
                );
                return Ok(ip);
            }
            Err(e) => {
                debug!(
                    "DNS nameserver-policy {} failed for {}: {}",
                    server, domain, e
                );
            }
        }
    }

    // 1. Use proxy-server-nameserver if configured
    if !config.proxy_server_nameserver.is_empty() {
        for server in &config.proxy_server_nameserver {
            match query_server(domain, server).await {
                Ok(ip) => {
                    debug!(
                        "DNS proxy-server-nameserver resolved {} -> {} via {}",
                        domain, ip, server
                    );
                    return Ok(ip);
                }
                Err(e) => {
                    debug!(
                        "DNS proxy-server-nameserver {} failed for {}: {}",
                        server, domain, e
                    );
                }
            }
        }
    }

    // 2. Fall back to default-nameserver (bootstrap DNS)
    if !config.default_nameserver.is_empty() {
        for server in &config.default_nameserver {
            match query_server(domain, server).await {
                Ok(ip) => {
                    debug!(
                        "DNS default-nameserver resolved {} -> {} via {}",
                        domain, ip, server
                    );
                    return Ok(ip);
                }
                Err(e) => {
                    debug!(
                        "DNS default-nameserver {} failed for {}: {}",
                        server, domain, e
                    );
                }
            }
        }
    }

    // 3. Fall back to system resolver (like mihomo's SystemResolver)
    // This uses the OS /etc/resolv.conf DNS
    match tokio::net::lookup_host(format!("{}:0", domain)).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                debug!(
                    "DNS system resolver resolved {} -> {}",
                    domain,
                    addr.ip()
                );
                return Ok(addr.ip());
            }
        }
        Err(e) => {
            debug!("DNS system resolver failed for {}: {}", domain, e);
        }
    }

    Err(anyhow::anyhow!(
        "all DNS servers failed for proxy server '{}' \
         (proxy-server-nameserver, default-nameserver, and system resolver all failed)",
        domain
    ))
}

/// Resolve a domain by querying upstream DNS servers.
///
/// Implements fallback logic: queries primary nameservers first, and if the
/// response looks suspicious (private IP for a public domain, or an IP in the
/// fake-ip range), re-queries using fallback nameservers.
pub async fn resolve(domain: &str, config: &DnsConfig) -> Result<IpAddr> {
    // Determine primary nameserver list
    let servers = if !config.nameserver.is_empty() {
        &config.nameserver
    } else if !config.default_nameserver.is_empty() {
        &config.default_nameserver
    } else {
        // Hardcoded fallback
        return resolve_udp(domain, "8.8.8.8:53").await;
    };

    // Try primary nameservers
    let mut primary_result: Option<IpAddr> = None;
    for server in servers {
        let result = query_server(domain, server).await;
        if let Ok(ip) = result {
            primary_result = Some(ip);
            break;
        }
    }

    // If we got a result, check if it needs fallback
    if let Some(ip) = primary_result {
        if should_use_fallback(&ip, domain, config) && !config.fallback.is_empty() {
            debug!(
                "DNS primary returned {} for {}, trying fallback servers",
                ip, domain
            );
            // Try fallback nameservers
            for server in &config.fallback {
                let result = query_server(domain, server).await;
                if let Ok(fallback_ip) = result {
                    debug!(
                        "DNS fallback returned {} for {} (primary was {})",
                        fallback_ip, domain, ip
                    );
                    return Ok(fallback_ip);
                }
            }
            // All fallbacks failed, return the primary result anyway
            return Ok(ip);
        }
        return Ok(ip);
    }

    // Primary failed entirely, try fallback servers
    if !config.fallback.is_empty() {
        for server in &config.fallback {
            let result = query_server(domain, server).await;
            if let Ok(ip) = result {
                return Ok(ip);
            }
        }
    }

    Err(anyhow::anyhow!("all DNS servers failed for {}", domain))
}

/// Check whether the primary DNS result looks suspicious and fallback should
/// be used.
///
/// The response is considered suspicious if:
/// - The IP is a private/reserved address for what appears to be a public domain.
/// - The IP falls within the fake-ip CIDR range.
/// - The fallback-filter config rules trigger (geoip, ipcidr, domain).
fn should_use_fallback(ip: &IpAddr, domain: &str, config: &DnsConfig) -> bool {
    // Never fallback for local-looking domains
    if domain.ends_with(".local")
        || domain.ends_with(".lan")
        || domain.ends_with(".internal")
        || domain == "localhost"
    {
        return false;
    }

    // Check if the IP is in the fake-ip range
    if let IpAddr::V4(v4) = ip {
        let fake_range = &config.fake_ip_range;
        if !fake_range.is_empty() {
            if let Ok((base, prefix_len)) = parse_cidr_simple(fake_range) {
                let mask = if prefix_len >= 32 {
                    0xFFFF_FFFFu32
                } else {
                    !((1u32 << (32 - prefix_len)) - 1)
                };
                let ip_u32 = u32::from(*v4);
                if ip_u32 & mask == base & mask {
                    return true;
                }
            }
        }
    }

    // Check if the IP is a private/reserved address
    if is_private_ip(ip) {
        return true;
    }

    // Check fallback-filter rules if present
    if let Some(ref filter) = config.fallback_filter {
        // GeoIP filter: if the resolved IP's country matches geoip_code,
        // the domain is likely being DNS-poisoned to a domestic IP.
        // Use fallback to get the real (overseas) answer.
        if filter.geoip && !filter.geoip_code.is_empty() {
            if let Some(country) = DNS_GEOIP.lookup_country(ip) {
                if country.eq_ignore_ascii_case(&filter.geoip_code) {
                    debug!(
                        "DNS fallback triggered: {} resolved to {} (country {}), matches geoip filter {}",
                        domain, ip, country, filter.geoip_code
                    );
                    return true;
                }
            }
        }

        // IP CIDR filter
        for cidr_str in &filter.ipcidr {
            if let Ok((base, prefix_len)) = parse_cidr_simple(cidr_str) {
                if let IpAddr::V4(v4) = ip {
                    let mask = if prefix_len >= 32 {
                        0xFFFF_FFFFu32
                    } else {
                        !((1u32 << (32 - prefix_len)) - 1)
                    };
                    let ip_u32 = u32::from(*v4);
                    if ip_u32 & mask == base & mask {
                        return true;
                    }
                }
            }
        }

        // Domain filter
        for d in &filter.domain {
            if let Some(suffix) = d.strip_prefix('+') {
                if domain.ends_with(suffix) {
                    return true;
                }
            } else if domain == d || domain.ends_with(&format!(".{}", d)) {
                return true;
            }
        }
    }

    false
}

/// Check whether an IP is in a private/reserved range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            // 0.0.0.0/8
            if octets[0] == 0 {
                return true;
            }
            // 169.254.0.0/16 (link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Simple CIDR parser returning (base_u32, prefix_len).
fn parse_cidr_simple(cidr: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("invalid CIDR: {}", cidr));
    }
    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    Ok((u32::from(ip), prefix_len))
}

/// Route a DNS query to the appropriate upstream based on the server URL scheme.
async fn query_server(domain: &str, server: &str) -> Result<IpAddr> {
    if server.starts_with("https://") {
        resolve_doh(domain, server).await
    } else if server.starts_with("tls://") {
        resolve_dot(domain, server).await
    } else {
        let addr = if server.contains(':') {
            server.to_string()
        } else {
            format!("{}:53", server)
        };
        resolve_udp(domain, &addr).await
    }
}

// ---------------------------------------------------------------------------
// Plain UDP DNS
// ---------------------------------------------------------------------------

/// Resolve via plain UDP DNS.
async fn resolve_udp(domain: &str, server: &str) -> Result<IpAddr> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DNS server address {}: {}", server, e))?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(addr).await?;

    let query = build_dns_query(domain, 1); // Type A = 1
    socket.send(&query).await?;

    let mut buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf));

    let n = timeout.await??;
    let response = &buf[..n];

    parse_dns_response(response)
}

// ---------------------------------------------------------------------------
// DNS-over-HTTPS
// ---------------------------------------------------------------------------

/// Resolve via DNS-over-HTTPS (RFC 8484).
async fn resolve_doh(domain: &str, url: &str) -> Result<IpAddr> {
    let query = build_dns_query(domain, 1);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);

    let request_url = format!("{}?dns={}", url, encoded);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let response = client
        .get(&request_url)
        .header("Accept", "application/dns-message")
        .send()
        .await?;

    let body = response.bytes().await?;
    parse_dns_response(&body)
}

use base64::Engine;

// ---------------------------------------------------------------------------
// DNS-over-TLS (DoT)
// ---------------------------------------------------------------------------

/// Global connection pool for DoT servers.
/// Maps server address to a pooled TLS connection.
type DotPool = Mutex<
    std::collections::HashMap<
        String,
        Arc<Mutex<Option<tokio_rustls::client::TlsStream<TcpStream>>>>,
    >,
>;
static DOT_POOL: std::sync::LazyLock<DotPool> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Resolve via DNS-over-TLS (RFC 7858).
///
/// Connects to the server on port 853, wraps the TCP connection in TLS,
/// and sends/receives DNS messages with 2-byte length prefix framing.
/// Connections are pooled for reuse.
async fn resolve_dot(domain: &str, server: &str) -> Result<IpAddr> {
    let addr_str = server.trim_start_matches("tls://");
    let (host, port_str) = if let Some(idx) = addr_str.rfind(':') {
        // Check if this is an IPv6 address in brackets
        if addr_str.starts_with('[') {
            if let Some(bracket_end) = addr_str.find(']') {
                if idx > bracket_end {
                    (&addr_str[..idx], &addr_str[idx + 1..])
                } else {
                    (addr_str, "853")
                }
            } else {
                (addr_str, "853")
            }
        } else {
            (&addr_str[..idx], &addr_str[idx + 1..])
        }
    } else {
        (addr_str, "853")
    };

    let port: u16 = port_str.parse().unwrap_or(853);
    let sock_addr = format!("{}:{}", host, port);
    let sni = host.to_string();

    // Try to reuse a pooled connection
    let pool_key = sock_addr.clone();
    let conn_slot = {
        let mut pool = DOT_POOL.lock().await;
        pool.entry(pool_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    };

    // Try the pooled connection first
    {
        let mut slot = conn_slot.lock().await;
        if let Some(ref mut tls_stream) = *slot {
            match dot_query_on_stream(tls_stream, domain).await {
                Ok(ip) => return Ok(ip),
                Err(_) => {
                    // Connection is stale, drop it and create a new one
                    *slot = None;
                }
            }
        }
    }

    // No pooled connection, create a new one
    let tcp_stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&sock_addr),
    )
    .await??;

    let tls_opts = TlsOptions {
        sni: sni.clone(),
        skip_cert_verify: false,
        alpn: vec![],
        fingerprint: None,
    };

    let mut tls_stream = wrap_tls(tcp_stream, &tls_opts).await?;
    let ip = dot_query_on_stream(&mut tls_stream, domain).await?;

    // Pool the connection for reuse
    {
        let mut slot = conn_slot.lock().await;
        *slot = Some(tls_stream);
    }

    Ok(ip)
}

/// Send a DNS query on an existing DoT TLS stream and read the response.
async fn dot_query_on_stream(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    domain: &str,
) -> Result<IpAddr> {
    let query = build_dns_query(domain, 1);

    // Write 2-byte length prefix + query
    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(&query).await?;
    stream.flush().await?;

    // Read 2-byte length prefix
    let mut resp_len_buf = [0u8; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut resp_len_buf),
    )
    .await??;

    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    if resp_len == 0 || resp_len > 65535 {
        return Err(anyhow::anyhow!("invalid DoT response length: {}", resp_len));
    }

    // Read the DNS response
    let mut resp_buf = vec![0u8; resp_len];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut resp_buf),
    )
    .await??;

    parse_dns_response(&resp_buf)
}

// ---------------------------------------------------------------------------
// DNS wire format helpers
// ---------------------------------------------------------------------------

/// Build a DNS query packet for the given domain and record type.
fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);

    // Header
    let id: u16 = rand_u16();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
    query.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    query.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    query.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    query.extend_from_slice(&[0x00, 0x00]); // Additional: 0

    // Question
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0); // End of domain

    query.extend_from_slice(&qtype.to_be_bytes()); // Type
    query.extend_from_slice(&[0x00, 0x01]); // Class IN

    query
}

/// Parse a DNS response and extract the first A record IP.
fn parse_dns_response(data: &[u8]) -> Result<IpAddr> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("DNS response too short"));
    }

    let _flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    if ancount == 0 {
        return Err(anyhow::anyhow!("no answers in DNS response"));
    }

    // Skip question section
    let mut pos = 12;
    for _ in 0..qdcount {
        // Skip name
        pos = skip_dns_name(data, pos)?;
        pos += 4; // Skip type + class
    }

    // Parse answer section
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= data.len() {
            // A record
            return Ok(IpAddr::V4(Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            )));
        }

        pos += rdlength;
    }

    Err(anyhow::anyhow!("no A record found in DNS response"))
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= data.len() {
            return Err(anyhow::anyhow!("truncated DNS name"));
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

/// Match a domain against nameserver-policy entries.
///
/// Policy keys can be:
/// - `"+.domain.com"` — matches domain.com and all subdomains
/// - `"domain.com"` — exact match
/// - `"geosite:xxx"` — not supported yet, returns None
///
/// Policy values can be a string (single server) or YAML array.
fn match_nameserver_policy(
    domain: &str,
    policy: &std::collections::HashMap<String, serde_yaml::Value>,
) -> Option<String> {
    let domain_lower = domain.to_lowercase();

    for (pattern, value) in policy {
        let pattern_lower = pattern.to_lowercase();

        // Skip geosite: patterns (not supported in proxy server resolution)
        if pattern_lower.starts_with("geosite:") {
            continue;
        }

        let matches = if let Some(suffix) = pattern_lower.strip_prefix("+.") {
            // "+.domain.com" matches "domain.com" and "*.domain.com"
            domain_lower == suffix || domain_lower.ends_with(&format!(".{}", suffix))
        } else {
            domain_lower == pattern_lower
        };

        if matches {
            // Extract server string from YAML value
            let server = match value {
                serde_yaml::Value::String(s) => Some(s.clone()),
                serde_yaml::Value::Sequence(seq) => {
                    // Use first server in the list
                    seq.first().and_then(|v| v.as_str().map(String::from))
                }
                _ => None,
            };
            if let Some(s) = server {
                return Some(s);
            }
        }
    }

    None
}

fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (t.subsec_nanos() ^ t.as_secs() as u32) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // ---- is_private_ip tests ----

    #[test]
    fn is_private_ip_10_range() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
    }

    #[test]
    fn is_private_ip_172_16_range() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        // 172.15.x.x is NOT private.
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1))));
        // 172.32.x.x is NOT private.
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    #[test]
    fn is_private_ip_192_168_range() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 255, 255
        ))));
    }

    #[test]
    fn is_private_ip_loopback() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn is_private_ip_link_local() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    #[test]
    fn is_private_ip_zero_range() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn is_private_ip_public() {
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    // ---- parse_cidr_simple tests ----

    #[test]
    fn parse_cidr_valid() {
        let (base, prefix) = parse_cidr_simple("198.18.0.0/15").unwrap();
        assert_eq!(base, u32::from(Ipv4Addr::new(198, 18, 0, 0)));
        assert_eq!(prefix, 15);
    }

    #[test]
    fn parse_cidr_host() {
        let (base, prefix) = parse_cidr_simple("10.0.0.1/32").unwrap();
        assert_eq!(base, u32::from(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn parse_cidr_invalid_no_slash() {
        assert!(parse_cidr_simple("192.168.1.0").is_err());
    }

    #[test]
    fn parse_cidr_invalid_bad_ip() {
        assert!(parse_cidr_simple("not.an.ip/24").is_err());
    }

    // ---- build_dns_query tests ----

    #[test]
    fn build_dns_query_structure() {
        let query = build_dns_query("example.com", 1);

        // DNS header is 12 bytes.
        assert!(query.len() >= 12);

        // Flags: 0x0100 (standard query, recursion desired).
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);

        // Question count = 1.
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);

        // Answer, authority, additional counts = 0.
        assert_eq!(query[6], 0x00);
        assert_eq!(query[7], 0x00);
        assert_eq!(query[8], 0x00);
        assert_eq!(query[9], 0x00);
        assert_eq!(query[10], 0x00);
        assert_eq!(query[11], 0x00);

        // Question section starts at byte 12.
        // "example" = 7 bytes, "com" = 3 bytes.
        assert_eq!(query[12], 7); // length of "example"
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3); // length of "com"
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0); // end of name

        // Type A = 0x0001.
        assert_eq!(query[25], 0x00);
        assert_eq!(query[26], 0x01);

        // Class IN = 0x0001.
        assert_eq!(query[27], 0x00);
        assert_eq!(query[28], 0x01);
    }

    // ---- should_use_fallback tests ----

    #[test]
    fn should_use_fallback_local_domain() {
        let config = DnsConfig::default();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Local-looking domains should never trigger fallback.
        assert!(!should_use_fallback(&ip, "router.local", &config));
        assert!(!should_use_fallback(&ip, "myhost.lan", &config));
        assert!(!should_use_fallback(&ip, "localhost", &config));
        assert!(!should_use_fallback(&ip, "internal.internal", &config));
    }

    #[test]
    fn should_use_fallback_private_ip() {
        let config = DnsConfig::default();
        // A private IP for a public domain is suspicious.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(should_use_fallback(&ip, "google.com", &config));
    }

    #[test]
    fn should_use_fallback_fake_ip_range() {
        let config = DnsConfig {
            fake_ip_range: "198.18.0.0/15".to_string(),
            ..Default::default()
        };
        // An IP inside the fake-ip range is suspicious.
        let ip = IpAddr::V4(Ipv4Addr::new(198, 18, 1, 1));
        assert!(should_use_fallback(&ip, "google.com", &config));
    }

    #[test]
    fn should_use_fallback_public_ip_no_filter() {
        let config = DnsConfig {
            fake_ip_range: "198.18.0.0/15".to_string(),
            fallback_filter: None,
            ..Default::default()
        };
        // A public, non-fake IP with no fallback filter should not trigger.
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!should_use_fallback(&ip, "example.com", &config));
    }

    // ---- parse_dns_response tests ----

    #[test]
    fn parse_dns_response_too_short() {
        assert!(parse_dns_response(&[0u8; 5]).is_err());
    }

    #[test]
    fn parse_dns_response_no_answers() {
        // Minimal DNS response header with 0 answers.
        let data = vec![0u8; 12];
        // ancount = 0 (bytes 6-7 already zero).
        assert!(parse_dns_response(&data).is_err());
    }
}
