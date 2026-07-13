use anyhow::Result;
use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, warn};

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

/// Shared scaffolding for racing multiple DNS servers concurrently
/// (mihomo batchExchange): one query task per server, first result accepted
/// by `filter` wins. `filter` receives a display label for the answering
/// server (empty in the single-server path, " <server>" otherwise) so error
/// messages can name it. Errors are optionally warned and the last one is
/// returned if every server fails.
async fn batch_resolve_inner<T, F>(
    domain: &str,
    servers: &[String],
    qtype: u16,
    warn_errors: bool,
    filter: F,
) -> Result<T>
where
    F: Fn(&str, IpAddr, u32) -> Result<T>,
{
    if servers.is_empty() {
        return Err(anyhow::anyhow!("no DNS servers configured"));
    }
    if servers.len() == 1 {
        let (ip, ttl) = query_server(domain, &servers[0], qtype).await?;
        return filter("", ip, ttl);
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(servers.len());
    for server in servers {
        let tx = tx.clone();
        let domain = domain.to_string();
        let server = server.clone();
        tokio::spawn(async move {
            let result = query_server(&domain, &server, qtype).await;
            let _ = tx.send((server, result)).await;
        });
    }
    drop(tx);

    let mut last_err = anyhow::anyhow!("all DNS servers failed for {domain}");
    while let Some((server, result)) = rx.recv().await {
        match result.and_then(|(ip, ttl)| filter(&format!(" {server}"), ip, ttl)) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if warn_errors {
                    warn!("{}", e);
                }
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// Race multiple DNS servers concurrently, return first successful result.
/// Matches mihomo's batchExchange() pattern. Returns (IP, TTL).
async fn batch_resolve(domain: &str, servers: &[String], qtype: u16) -> Result<(IpAddr, u32)> {
    batch_resolve_inner(domain, servers, qtype, false, |_server, ip, ttl| {
        Ok((ip, ttl))
    })
    .await
}

/// Race multiple DNS servers concurrently, rejecting FakeIP results.
/// Returns the first successful non-FakeIP result.
async fn batch_resolve_reject_fakeip(
    domain: &str,
    servers: &[String],
    fake_ip_range: &str,
    source_label: &str,
) -> Result<IpAddr> {
    batch_resolve_inner(domain, servers, 1, true, |server, ip, _ttl| {
        if is_in_fakeip_range(&ip, fake_ip_range) {
            Err(anyhow::anyhow!(
                "DNS {source_label}{server} returned FakeIP {ip} for proxy server {domain}, rejecting"
            ))
        } else {
            Ok(ip)
        }
    })
    .await
}

/// Resolve a proxy server hostname using only direct/bootstrap DNS.
///
/// Uses `proxy-server-nameserver` if configured, otherwise falls back to
/// `default-nameserver`. These are typically plain UDP servers (e.g.
/// 114.114.114.114) set by OpenClash, avoiding the circular dependency
/// where DoH/DoT nameservers need a proxy but the proxy needs DNS first.
///
/// Within each tier, all servers are raced concurrently (mihomo batchExchange).
pub async fn resolve_proxy_server(domain: &str, config: &DnsConfig) -> Result<IpAddr> {
    // 0. Check nameserver-policy first (e.g. "+.oix_nodes.com": "124.221.68.73:1053")
    if let Some(server) = match_nameserver_policy(domain, &config.nameserver_policy) {
        match query_server(domain, &server, 1).await {
            Ok((ip, _ttl)) => {
                if is_in_fakeip_range(&ip, &config.fake_ip_range) {
                    warn!(
                        "DNS nameserver-policy {} returned FakeIP {} for proxy server {}, rejecting",
                        server, ip, domain
                    );
                } else {
                    debug!(
                        "DNS nameserver-policy resolved {} -> {} via {}",
                        domain, ip, server
                    );
                    return Ok(ip);
                }
            }
            Err(e) => {
                warn!(
                    "DNS nameserver-policy {} failed for {}: {}",
                    server, domain, e
                );
            }
        }
    } else {
        debug!(
            "DNS no nameserver-policy match for {} (policies: {:?})",
            domain,
            config.nameserver_policy.keys().collect::<Vec<_>>()
        );
    }

    // 1. Use proxy-server-nameserver if configured — race all concurrently
    if !config.proxy_server_nameserver.is_empty() {
        match batch_resolve_reject_fakeip(
            domain,
            &config.proxy_server_nameserver,
            &config.fake_ip_range,
            "proxy-server-nameserver",
        )
        .await
        {
            Ok(ip) => {
                debug!("DNS proxy-server-nameserver resolved {} -> {}", domain, ip);
                return Ok(ip);
            }
            Err(e) => {
                warn!(
                    "DNS proxy-server-nameserver all failed for {}: {}",
                    domain, e
                );
            }
        }
    }

    // 2. Fall back to default-nameserver (bootstrap DNS) — race all concurrently
    if !config.default_nameserver.is_empty() {
        match batch_resolve_reject_fakeip(
            domain,
            &config.default_nameserver,
            &config.fake_ip_range,
            "default-nameserver",
        )
        .await
        {
            Ok(ip) => {
                debug!("DNS default-nameserver resolved {} -> {}", domain, ip);
                return Ok(ip);
            }
            Err(e) => {
                warn!("DNS default-nameserver all failed for {}: {}", domain, e);
            }
        }
    }

    // mihomo compat: NO system resolver fallback for proxy server hostnames.
    // On routers, /etc/resolv.conf typically points to the local DNS server
    // (127.0.0.1 or FakeIP hijack address), which would cause a circular
    // dependency: proxy needs DNS → DNS server → resolve() → FakeIP allocated
    // → proxy connects to FakeIP → timeout.
    Err(anyhow::anyhow!(
        "all DNS servers failed for proxy server '{domain}' \
         (nameserver-policy, proxy-server-nameserver, and default-nameserver all failed)"
    ))
}

/// Resolve a domain by querying upstream DNS servers.
///
/// Implements fallback logic: races all primary nameservers concurrently
/// (mihomo batchExchange), and if the result looks suspicious (private IP
/// for a public domain, or an IP in the fake-ip range), races all fallback
/// servers concurrently.
pub async fn resolve(domain: &str, config: &DnsConfig) -> Result<(IpAddr, u32)> {
    resolve_qtype(domain, config, 1).await
}

/// Race a specific server list (nameserver-policy hit) — no fallback logic.
/// mihomo compat: resolver.go matchPolicy results are used directly.
pub async fn resolve_via(domain: &str, servers: &[String], qtype: u16) -> Result<(IpAddr, u32)> {
    batch_resolve(domain, servers, qtype).await
}

/// The first configured main nameserver usable for raw passthrough (plain
/// "ip" / "ip:port" UDP entries only).
pub fn plain_udp_server(config: &DnsConfig) -> Option<String> {
    config
        .nameserver
        .iter()
        .chain(config.default_nameserver.iter())
        .find_map(|s| {
            if s.contains("://") || s == "system" {
                return None;
            }
            if s.parse::<std::net::SocketAddr>().is_ok() {
                return Some(s.clone());
            }
            s.parse::<IpAddr>().ok().map(|ip| match ip {
                IpAddr::V4(_) => format!("{ip}:53"),
                IpAddr::V6(_) => format!("[{ip}]:53"),
            })
        })
}

pub async fn resolve_qtype(domain: &str, config: &DnsConfig, qtype: u16) -> Result<(IpAddr, u32)> {
    // Determine primary nameserver list
    let servers = if !config.nameserver.is_empty() {
        &config.nameserver
    } else if !config.default_nameserver.is_empty() {
        &config.default_nameserver
    } else {
        // Hardcoded fallback
        return resolve_udp(domain, "8.8.8.8:53", qtype).await;
    };

    // Race all primary nameservers concurrently
    let primary_result = batch_resolve(domain, servers, qtype).await;

    // If we got a result, check if it needs fallback
    if let Ok((ip, ttl)) = primary_result {
        if should_use_fallback(&ip, domain, config) && !config.fallback.is_empty() {
            debug!(
                "DNS primary returned {} for {}, trying fallback servers",
                ip, domain
            );
            // Race all fallback nameservers concurrently
            match batch_resolve(domain, &config.fallback, qtype).await {
                Ok((fallback_ip, fallback_ttl)) => {
                    debug!(
                        "DNS fallback returned {} for {} (primary was {})",
                        fallback_ip, domain, ip
                    );
                    return Ok((fallback_ip, fallback_ttl));
                }
                Err(_) => {
                    // All fallbacks failed, return the primary result anyway
                    return Ok((ip, ttl));
                }
            }
        }
        return Ok((ip, ttl));
    }

    // Primary failed entirely, try fallback servers concurrently
    if !config.fallback.is_empty() {
        if let Ok(result) = batch_resolve(domain, &config.fallback, qtype).await {
            return Ok(result);
        }
    }

    Err(anyhow::anyhow!("all DNS servers failed for {domain}"))
}

/// Check whether the primary DNS result looks suspicious and fallback should
/// be used.
///
/// Mirrors mihomo's `Resolver.shouldIPFallback` composed of the configured
/// `fallback-filter` matchers (`dns/resolver.go:119-137`, `rules/common/geoip.go`
/// `dnsFallbackFilter.MatchIp`):
/// - LAN / private / reserved IPs never trigger fallback (`geoip.go:127-130`).
/// - GeoIP filter triggers fallback when the IP's country does **not** match
///   `geoip-code` (`geoip.go:144` `return !slices.Contains(codes, g.country)`),
///   which includes the poisoned-foreign and unknown-country cases.
/// - IP-CIDR filter triggers fallback when the IP falls inside a listed range.
/// - Domain filter triggers fallback for matched domains (mihomo handles this as
///   a "query only fallback" short-circuit; the resulting answer is the same).
fn should_use_fallback(ip: &IpAddr, domain: &str, config: &DnsConfig) -> bool {
    // mihomo compat: dnsFallbackFilter.MatchIp returns false for LAN IPs
    // ("compatible with original behavior", geoip.go:127-130) — a private answer
    // from the trusted main resolver is kept, never overridden by fallback.
    if is_private_ip(ip) {
        return false;
    }

    // mihomo compat: fallback-filter defaults to {geoip: true, geoip-code: CN}
    // (config.go:503-508) and is active whenever `fallback:` is configured —
    // an omitted fallback-filter block still gets the GeoIP anti-poison filter.
    let (geoip_on, geoip_code) = match config.fallback_filter {
        Some(ref f) => (f.geoip, f.geoip_code.as_str()),
        None => (true, "CN"),
    };

    // GeoIP filter: fallback when the resolved IP's country does NOT match
    // geoip_code. A domestic (matching-country) answer from the main
    // nameserver is trusted; a foreign or unknown-country answer is treated
    // as potentially GFW-poisoned and re-queried through the fallback tier.
    if geoip_on && !geoip_code.is_empty() {
        let matches_code = DNS_GEOIP
            .lookup_codes(ip)
            .iter()
            .any(|country| country.eq_ignore_ascii_case(geoip_code));
        if !matches_code {
            debug!(
                "DNS fallback triggered: {} resolved to {} (country not {}), using fallback",
                domain, ip, geoip_code
            );
            return true;
        }
    }

    // Check the remaining fallback-filter rules if a block is present
    if let Some(ref filter) = config.fallback_filter {
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
            } else if domain == d || domain.ends_with(&format!(".{d}")) {
                return true;
            }
        }
    }

    false
}

/// Check whether an IP falls within the configured fake-ip CIDR range.
fn is_in_fakeip_range(ip: &IpAddr, fake_ip_range: &str) -> bool {
    if fake_ip_range.is_empty() {
        return false;
    }
    if let IpAddr::V4(v4) = ip {
        if let Ok((base, prefix_len)) = parse_cidr_simple(fake_ip_range) {
            let mask = if prefix_len >= 32 {
                0xFFFF_FFFFu32
            } else {
                !((1u32 << (32 - prefix_len)) - 1)
            };
            let ip_u32 = u32::from(*v4);
            return ip_u32 & mask == base & mask;
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
        return Err(anyhow::anyhow!("invalid CIDR: {cidr}"));
    }
    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    Ok((u32::from(ip), prefix_len))
}

/// Route a DNS query to the appropriate upstream based on the server URL scheme.
/// Returns (IP, TTL).
async fn query_server(domain: &str, server: &str, qtype: u16) -> Result<(IpAddr, u32)> {
    // Strip quotes that OpenClash sometimes leaves (e.g. dhcp://"eth1")
    let server = server.trim_matches('"').trim_matches('\'');

    if server.starts_with("https://") {
        resolve_doh(domain, server, qtype).await
    } else if server.starts_with("tls://") {
        resolve_dot(domain, server, qtype).await
    } else if server.starts_with("dhcp://") {
        // mihomo's `dns/dhcp.go` reads DNS from the DHCP lease on the named
        // interface. miemietron does not have a DHCP client — surface that as
        // an explicit error rather than silently falling back to the system
        // resolver, which would change routing/policy behavior in ways the
        // operator did not configure.
        Err(anyhow::anyhow!(
            "DNS scheme not supported: {server} (dhcp:// requires a DHCP client; out of scope — see ARCHITECTURE.md)"
        ))
    } else if server.starts_with("quic://") || server.starts_with("h3://") {
        // mihomo's `dns/doq.go` and DoH-over-H3 — both require a QUIC stack
        // we don't yet ship. Fail loudly instead of silently masquerading.
        Err(anyhow::anyhow!(
            "DNS scheme not supported: {server} (DoQ / DoH-H3 out of scope — see ARCHITECTURE.md)"
        ))
    } else if server.starts_with("system://") || server == "system" {
        resolve_system(domain).await
    } else {
        let addr = if server.contains(':') {
            server.to_string()
        } else {
            format!("{server}:53")
        };
        resolve_udp(domain, &addr, qtype).await
    }
}

/// System DNS resolver fallback via tokio's lookup_host.
/// Returns a default TTL of 60s since the system resolver doesn't expose TTL.
async fn resolve_system(domain: &str) -> Result<(IpAddr, u32)> {
    let host = format!("{domain}:0");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host).await?.collect();
    addrs
        .first()
        .map(|a| (a.ip(), 60)) // System resolver doesn't expose TTL; use 60s default
        .ok_or_else(|| anyhow::anyhow!("system resolver returned no results for {domain}"))
}

/// Resolve via plain UDP DNS. Returns (IP, TTL).
async fn resolve_udp(domain: &str, server: &str, qtype: u16) -> Result<(IpAddr, u32)> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DNS server address {server}: {e}"))?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // mihomo compat: DNS sockets go through the dialer which applies
    // DefaultRoutingMark (SO_MARK) only when routing-mark is configured.
    // When routing-mark is not set, GID 65534 (set by OpenClash via procd)
    // is the sole firewall bypass mechanism. Do NOT hardcode SO_MARK here —
    // it interferes with GID-only bypass on some OpenClash configurations.

    socket.connect(addr).await?;

    let query = build_dns_query(domain, qtype);
    socket.send(&query).await?;

    let mut buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf));

    let n = timeout.await??;
    let response = &buf[..n];

    parse_dns_response(response, qtype)
}

/// Shared HTTP client for DoH queries — built once so TCP+TLS connections
/// are pooled and reused across queries (mirrors DOT_POOL below).
static DOH_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to build DoH HTTP client")
});

/// Resolve via DNS-over-HTTPS (RFC 8484). Returns (IP, TTL).
async fn resolve_doh(domain: &str, url: &str, qtype: u16) -> Result<(IpAddr, u32)> {
    let query = build_dns_query(domain, qtype);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);

    let request_url = format!("{url}?dns={encoded}");

    let response = DOH_CLIENT
        .get(&request_url)
        .header("Accept", "application/dns-message")
        .send()
        .await?;

    let body = response.bytes().await?;
    parse_dns_response(&body, qtype)
}

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

/// Resolve via DNS-over-TLS (RFC 7858). Returns (IP, TTL).
///
/// Connects to the server on port 853, wraps the TCP connection in TLS,
/// and sends/receives DNS messages with 2-byte length prefix framing.
/// Connections are pooled for reuse.
async fn resolve_dot(domain: &str, server: &str, qtype: u16) -> Result<(IpAddr, u32)> {
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

    let port: u16 = port_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DNS server address {server}: {e}"))?;
    let sock_addr = format!("{host}:{port}");
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
            match dot_query_on_stream(tls_stream, domain, qtype).await {
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

    // mihomo compat: no hardcoded SO_MARK — GID 65534 handles bypass.

    let tls_opts = TlsOptions {
        sni: sni.clone(),
        skip_cert_verify: false,
        alpn: vec![],
        fingerprint: None,
    };

    let mut tls_stream = wrap_tls(tcp_stream, &tls_opts).await?;
    let ip = dot_query_on_stream(&mut tls_stream, domain, qtype).await?;

    // Pool the connection for reuse
    {
        let mut slot = conn_slot.lock().await;
        *slot = Some(tls_stream);
    }

    Ok(ip)
}

/// Send a DNS query on an existing DoT TLS stream and read the response. Returns (IP, TTL).
async fn dot_query_on_stream(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    domain: &str,
    qtype: u16,
) -> Result<(IpAddr, u32)> {
    let query = build_dns_query(domain, qtype);

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
    if resp_len == 0 {
        return Err(anyhow::anyhow!("invalid DoT response length: {resp_len}"));
    }

    // Read the DNS response
    let mut resp_buf = vec![0u8; resp_len];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut resp_buf),
    )
    .await??;

    parse_dns_response(&resp_buf, qtype)
}

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

/// Parse a DNS response and extract the first A record IP and the minimum TTL
/// from all answer records.
///
/// mihomo compat: returns (ip, min_ttl) where min_ttl is the smallest TTL
/// across all answer records (see dns/util.go minimalTTL).
fn parse_dns_response(data: &[u8], qtype: u16) -> Result<(IpAddr, u32)> {
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

    // Parse answer section — extract first A record IP and minimum TTL
    let mut result_ip: Option<IpAddr> = None;
    let mut min_ttl: u32 = u32::MAX;

    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        // Track minimum TTL across all answer records (mihomo compat)
        if ttl < min_ttl {
            min_ttl = ttl;
        }

        if rtype == 1 && qtype == 1 && rdlength == 4 && pos + 4 <= data.len() && result_ip.is_none()
        {
            // A record — take the first one
            result_ip = Some(IpAddr::V4(Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            )));
        } else if rtype == 28
            && qtype == 28
            && rdlength == 16
            && pos + 16 <= data.len()
            && result_ip.is_none()
        {
            // AAAA record — take the first one
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[pos..pos + 16]);
            result_ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
        }

        pos += rdlength;
    }

    match result_ip {
        Some(ip) => Ok((ip, if min_ttl == u32::MAX { 0 } else { min_ttl })),
        None => Err(anyhow::anyhow!("no matching record found in DNS response")),
    }
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

/// mihomo compat: DomainTrie insert semantics for policy/hosts keys —
/// "example.com" exact, "+.example.com" the domain and any subdomain,
/// "*.example.com" exactly one extra label.
pub(crate) fn domain_pattern_match(pattern: &str, domain: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("+.") {
        domain == suffix || domain.ends_with(&format!(".{suffix}"))
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.len() > suffix.len() + 1
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            && !domain[..domain.len() - suffix.len() - 1].contains('.')
    } else {
        domain == pattern
    }
}

/// Iterate nameserver-policy entries and return the server list of the first
/// key matching `domain`.
///
/// mihomo compat: config.go parseNameServerPolicy — a policy key can be a
/// comma-separated list of patterns; each trimmed, lowercased pattern (plain
/// domain patterns as well as `geosite:`/`rule-set:` prefixed ones) is fed to
/// `pattern_match` together with the lowercased domain. Values can be a
/// string (single server) or a YAML sequence.
pub(crate) fn find_nameserver_policy<F>(
    domain: &str,
    policy: &serde_yaml::Mapping,
    pattern_match: F,
) -> Option<Vec<String>>
where
    F: Fn(&str, &str) -> bool,
{
    let domain_lower = domain.to_lowercase();

    for (key, value) in policy {
        let Some(pattern_raw) = key.as_str() else {
            continue;
        };
        let matched = pattern_raw.split(',').any(|pattern| {
            let pattern = pattern.trim().to_lowercase();
            pattern_match(&pattern, &domain_lower)
        });
        if matched {
            let servers: Vec<String> = match value {
                serde_yaml::Value::String(s) => vec![s.clone()],
                serde_yaml::Value::Sequence(seq) => seq
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                _ => vec![],
            };
            if !servers.is_empty() {
                return Some(servers);
            }
        }
    }

    None
}

/// Match a domain against nameserver-policy entries, returning the first
/// server of the matched entry.
///
/// Policy keys can be:
/// - `"+.domain.com"` — matches domain.com and all subdomains
/// - `"domain.com"` — exact match
/// - `"geosite:xxx"` / `"rule-set:xxx"` — skipped: they need the rule engine,
///   which is not available in the proxy-server bootstrap path; the
///   resolver-level policy handles them
///   (DnsResolver::nameserver_policy_servers).
fn match_nameserver_policy(domain: &str, policy: &serde_yaml::Mapping) -> Option<String> {
    find_nameserver_policy(domain, policy, |pattern, domain| {
        if pattern.starts_with("geosite:") || pattern.starts_with("rule-set:") {
            return false;
        }
        domain_pattern_match(pattern, domain)
    })
    .and_then(|servers| servers.into_iter().next())
}

fn rand_u16() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

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

    #[test]
    fn should_use_fallback_private_ip_never() {
        // mihomo compat: dnsFallbackFilter.MatchIp returns false for LAN IPs
        // (geoip.go:127-130) even when a geoip filter is active — a private
        // answer from the trusted main resolver is kept, never overridden.
        let config = DnsConfig {
            fallback_filter: Some(crate::config::dns::FallbackFilter {
                geoip: true,
                geoip_code: "CN".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!should_use_fallback(&ip, "google.com", &config));
    }

    #[test]
    fn should_use_fallback_geoip_unknown_country() {
        // With a geoip filter active, an IP whose country does not match the
        // configured code (here: unknown, no mmdb loaded in tests) triggers
        // fallback — mihomo geoip.go:144 `!slices.Contains(codes, g.country)`.
        let config = DnsConfig {
            fallback_filter: Some(crate::config::dns::FallbackFilter {
                geoip: true,
                geoip_code: "CN".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(should_use_fallback(&ip, "google.com", &config));
    }

    #[test]
    fn should_use_fallback_ipcidr_match() {
        let config = DnsConfig {
            fallback_filter: Some(crate::config::dns::FallbackFilter {
                ipcidr: vec!["8.8.8.0/24".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let inside = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let outside = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert!(should_use_fallback(&inside, "example.com", &config));
        assert!(!should_use_fallback(&outside, "example.com", &config));
    }

    #[test]
    fn should_use_fallback_public_ip_no_filter() {
        let config = DnsConfig {
            fallback_filter: None,
            ..Default::default()
        };
        // mihomo compat: fallback-filter defaults to {geoip: true, geoip-code:
        // CN} (config.go:503-508) even when the block is omitted — a public
        // non-CN answer from the main nameservers triggers the fallback tier.
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(should_use_fallback(&ip, "example.com", &config));

        // Explicitly disabling geoip turns the anti-poison filter off.
        let config = DnsConfig {
            fallback_filter: Some(crate::config::dns::FallbackFilter {
                geoip: false,
                geoip_code: "CN".to_string(),
                geosite: vec![],
                ipcidr: vec![],
                domain: vec![],
            }),
            ..Default::default()
        };
        assert!(!should_use_fallback(&ip, "example.com", &config));
    }

    #[test]
    fn fakeip_range_match() {
        let range = "198.18.0.0/15";
        assert!(is_in_fakeip_range(
            &IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            range
        ));
        assert!(is_in_fakeip_range(
            &IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255)),
            range
        ));
        assert!(!is_in_fakeip_range(
            &IpAddr::V4(Ipv4Addr::new(198, 20, 0, 1)),
            range
        ));
        assert!(!is_in_fakeip_range(
            &IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            range
        ));
    }

    #[test]
    fn fakeip_range_empty() {
        assert!(!is_in_fakeip_range(
            &IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            ""
        ));
    }

    #[test]
    fn parse_dns_response_too_short() {
        assert!(parse_dns_response(&[0u8; 5], 1).is_err());
    }

    #[test]
    fn parse_dns_response_no_answers() {
        // Minimal DNS response header with 0 answers.
        let data = vec![0u8; 12];
        // ancount = 0 (bytes 6-7 already zero).
        assert!(parse_dns_response(&data, 1).is_err());
    }
}
