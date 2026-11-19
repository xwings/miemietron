use anyhow::Result;
use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;

use crate::config::DnsConfig;
use crate::rules::geoip::GeoIpMatcher;
use crate::transport::tls::{wrap_tls, TlsOptions};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;

const RCODE_SERVER_FAILURE: u8 = 2;
const RCODE_REFUSED: u8 = 5;

/// What a nameserver said about an A/AAAA question.
///
/// mihomo compat: mihomo hands the whole `*D.Msg` around; these are the parts
/// of it our replies and lookups are built from. An NXDOMAIN or empty reply is
/// an answer like any other — only SERVFAIL and REFUSED count as a failed
/// exchange (dns/util.go batchExchange).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The response code, relayed to the client as is.
    pub rcode: u8,
    /// The addresses of the requested type, in reply order.
    pub ips: Vec<IpAddr>,
    /// Seconds the reply may be cached for: the smallest TTL among its records
    /// (dns/util.go putMsgToCache), 0 for a reply that carries none.
    pub ttl: u32,
}

impl Answer {
    /// A successful reply without records (mihomo handleMsgWithEmptyAnswer).
    pub fn empty() -> Self {
        Self {
            rcode: 0,
            ips: Vec::new(),
            ttl: 0,
        }
    }

    /// The first address, or mihomo's `resolver.ErrIPNotFound`.
    pub fn first_ip(&self, domain: &str) -> Result<IpAddr> {
        self.ips
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("couldn't find ip: {domain}"))
    }
}

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

/// Race the nameservers concurrently; the first usable reply wins.
///
/// mihomo compat: dns/util.go batchExchange — a SERVFAIL or REFUSED reply
/// counts as that server failing (see `query_server`); any other reply,
/// NXDOMAIN and empty answers included, is the result.
async fn batch_resolve(domain: &str, servers: &[String], qtype: u16) -> Result<Answer> {
    if servers.is_empty() {
        return Err(anyhow::anyhow!("no DNS servers configured"));
    }
    if servers.len() == 1 {
        return query_server(domain, &servers[0], qtype)
            .await
            .map_err(|e| all_failed(Some(e)));
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(servers.len());
    for server in servers {
        let tx = tx.clone();
        let domain = domain.to_string();
        let server = server.clone();
        tokio::spawn(async move {
            let _ = tx.send(query_server(&domain, &server, qtype).await).await;
        });
    }
    drop(tx);

    let mut first_err = None;
    while let Some(result) = rx.recv().await {
        match result {
            Ok(answer) => return Ok(answer),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(all_failed(first_err))
}

/// mihomo compat: dns/util.go batchExchange — the error once every server of
/// a race has failed.
fn all_failed(first_err: Option<anyhow::Error>) -> anyhow::Error {
    match first_err {
        Some(e) => anyhow::anyhow!("all DNS requests failed, first error: {e}"),
        None => anyhow::anyhow!("all DNS requests failed"),
    }
}

/// Resolve a domain by querying upstream DNS servers.
///
/// Implements fallback logic: races all primary nameservers concurrently
/// (mihomo batchExchange), and if the result looks suspicious (private IP
/// for a public domain, or an IP in the fake-ip range), races all fallback
/// servers concurrently.
pub async fn resolve(domain: &str, config: &DnsConfig) -> Result<Answer> {
    resolve_qtype(domain, config, TYPE_A).await
}

/// Race a specific server list (nameserver-policy hit) — no fallback logic.
/// mihomo compat: resolver.go matchPolicy results are used directly.
pub async fn resolve_via(domain: &str, servers: &[String], qtype: u16) -> Result<Answer> {
    batch_resolve(domain, servers, qtype).await
}

/// The first configured main nameserver usable for raw passthrough (plain
/// "ip" / "ip:port" UDP entries only).
pub fn plain_udp_server(config: &DnsConfig) -> Option<SocketAddr> {
    config
        .nameserver
        .iter()
        .chain(config.default_nameserver.iter())
        .find_map(|s| {
            if s.contains("://") || s == "system" {
                return None;
            }
            s.parse::<SocketAddr>()
                .ok()
                .or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
        })
}

pub async fn resolve_qtype(domain: &str, config: &DnsConfig, qtype: u16) -> Result<Answer> {
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

    // mihomo compat: resolver.go ipExchange — "directly return if no fallback
    // servers are available". The fallback filters, and the GeoIP database
    // behind them, only exist for a config that has fallback servers.
    if config.fallback.is_empty() {
        return primary_result;
    }

    // mihomo compat: ipExchange — the main answer stands when it carries
    // addresses and none of them trips a fallback filter.
    if let Ok(answer) = primary_result {
        if !answer.ips.is_empty()
            && !answer
                .ips
                .iter()
                .any(|ip| should_use_fallback(ip, domain, config))
        {
            return Ok(answer);
        }
        debug!(
            "DNS primary returned {:?} for {}, trying fallback servers",
            answer.ips, domain
        );
        // Race all fallback nameservers concurrently
        return match batch_resolve(domain, &config.fallback, qtype).await {
            Ok(fallback) => {
                debug!(
                    "DNS fallback returned {:?} for {} (primary was {:?})",
                    fallback.ips, domain, answer.ips
                );
                Ok(fallback)
            }
            // All fallbacks failed, return the primary result anyway
            Err(_) => Ok(answer),
        };
    }

    // Primary failed entirely, try fallback servers concurrently
    batch_resolve(domain, &config.fallback, qtype).await
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
///
/// mihomo compat: dns/util.go batchExchange — a SERVFAIL or REFUSED reply is a
/// failed exchange ("server failure: SERVFAIL"), not an answer.
async fn query_server(domain: &str, server: &str, qtype: u16) -> Result<Answer> {
    // Strip quotes that OpenClash sometimes leaves (e.g. dhcp://"eth1")
    let server = server.trim_matches('"').trim_matches('\'');

    let answer = if server.starts_with("https://") {
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
    }?;

    match answer.rcode {
        RCODE_SERVER_FAILURE => Err(anyhow::anyhow!("server failure: SERVFAIL")),
        RCODE_REFUSED => Err(anyhow::anyhow!("server failure: REFUSED")),
        _ => Ok(answer),
    }
}

/// System DNS resolver fallback via tokio's lookup_host.
/// Reports a default TTL of 60s since the system resolver doesn't expose TTL.
async fn resolve_system(domain: &str) -> Result<Answer> {
    let host = format!("{domain}:0");
    let ips: Vec<IpAddr> = tokio::net::lookup_host(&host)
        .await?
        .map(|addr| addr.ip())
        .collect();
    if ips.is_empty() {
        return Err(anyhow::anyhow!(
            "system resolver returned no results for {domain}"
        ));
    }
    Ok(Answer {
        rcode: 0,
        ips,
        ttl: 60,
    })
}

/// Resolve via plain UDP DNS.
async fn resolve_udp(domain: &str, server: &str, qtype: u16) -> Result<Answer> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DNS server address {server}: {e}"))?;

    let query = build_dns_query(domain, qtype);
    let mut response = exchange_udp(addr, &query).await?;
    // mihomo compat: dns/client.go — "Resolvers MUST resend queries over TCP
    // if they receive a truncated UDP response (with TC=1 set)!"
    if is_truncated(&response) {
        debug!(
            "[DNS] Truncated reply from {} for {} over UDP, retrying over TCP",
            addr, domain
        );
        response = exchange_tcp(addr, &query).await?;
    }

    parse_dns_response(&response, qtype)
}

/// Exchange one DNS message with a nameserver over UDP.
pub(super) async fn exchange_udp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    // mihomo compat: DNS sockets go through the dialer, which binds them to
    // DefaultInterface (dialer.go:183-189) and applies DefaultRoutingMark
    // (SO_MARK) only when routing-mark is configured. When routing-mark is not
    // set, GID 65534 (set by OpenClash via procd) is the sole firewall bypass
    // mechanism. Do NOT hardcode SO_MARK here — it interferes with GID-only
    // bypass on some OpenClash configurations.
    let socket = crate::transport::tcp::bind_udp_default_interface()?;

    socket.connect(server).await?;
    socket.send(query).await?;

    let mut buf = vec![0u8; 4096];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf));

    let n = timeout.await??;
    buf.truncate(n);
    Ok(buf)
}

/// Exchange one DNS message with a nameserver over TCP.
pub(super) async fn exchange_tcp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::transport::tcp::connect(server, &crate::transport::tcp::ConnectOpts::default()),
    )
    .await??;
    exchange_on_stream(&mut stream, query).await
}

/// Whether a DNS message has the TC (truncated) bit set.
pub(super) fn is_truncated(message: &[u8]) -> bool {
    message.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

/// Shared HTTP client for DoH queries — built once so TCP+TLS connections
/// are pooled and reused across queries (mirrors DOT_POOL below).
static DOH_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to build DoH HTTP client")
});

/// Resolve via DNS-over-HTTPS (RFC 8484).
async fn resolve_doh(domain: &str, url: &str, qtype: u16) -> Result<Answer> {
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

/// Resolve via DNS-over-TLS (RFC 7858).
///
/// Connects to the server on port 853, wraps the TCP connection in TLS,
/// and sends/receives DNS messages with 2-byte length prefix framing.
/// Connections are pooled for reuse.
async fn resolve_dot(domain: &str, server: &str, qtype: u16) -> Result<Answer> {
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

    let query = build_dns_query(domain, qtype);

    // Try the pooled connection first
    {
        let mut slot = conn_slot.lock().await;
        if let Some(ref mut tls_stream) = *slot {
            match exchange_on_stream(tls_stream, &query).await {
                Ok(response) => return parse_dns_response(&response, qtype),
                Err(_) => {
                    // Connection is stale, drop it and create a new one
                    *slot = None;
                }
            }
        }
    }

    // No pooled connection, create a new one.
    //
    // mihomo compat: DoT dials through the dialer (dns/client.go:68), so it
    // binds to the global outbound interface like every other outbound.
    // No hardcoded SO_MARK — GID 65534 handles bypass.
    let tcp_stream = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let target = tokio::net::lookup_host(&sock_addr)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no address for DoT server {sock_addr}"))?;
        crate::transport::tcp::connect(target, &crate::transport::tcp::ConnectOpts::default()).await
    })
    .await??;

    let tls_opts = TlsOptions {
        sni: sni.clone(),
        skip_cert_verify: false,
        alpn: vec![],
        fingerprint: None,
    };

    let mut tls_stream = wrap_tls(tcp_stream, &tls_opts).await?;
    let response = exchange_on_stream(&mut tls_stream, &query).await?;

    // Pool the connection for reuse
    {
        let mut slot = conn_slot.lock().await;
        *slot = Some(tls_stream);
    }

    parse_dns_response(&response, qtype)
}

/// Send a DNS message on a stream transport (TCP, TLS) and read the reply:
/// 2-byte length prefix framing, RFC 1035 section 4.2.2.
async fn exchange_on_stream<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Write 2-byte length prefix + query
    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(query).await?;
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
        return Err(anyhow::anyhow!("invalid DNS response length: {resp_len}"));
    }

    // Read the DNS response
    let mut resp_buf = vec![0u8; resp_len];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut resp_buf),
    )
    .await??;

    Ok(resp_buf)
}

/// Build a DNS query packet for the given domain and record type.
pub(super) fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
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

/// Parse a DNS response into the answer the resolver works with: its response
/// code, the addresses of the requested type and its cache TTL.
///
/// mihomo compat: the TTL is the smallest one among the answer, authority and
/// additional records, OPT excluded (dns/util.go putMsgToCache → minimalTTL):
/// for an NXDOMAIN or empty reply that is the SOA in the authority section.
fn parse_dns_response(data: &[u8], qtype: u16) -> Result<Answer> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("DNS response too short"));
    }

    let rcode = data[3] & 0x0F;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    // Skip question section
    let mut pos = 12;
    for _ in 0..qdcount {
        // Skip name
        pos = skip_dns_name(data, pos)?;
        pos += 4; // Skip type + class
    }

    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;

    for index in 0..ancount + nscount + arcount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        // The TTL field of an OPT record holds flags, not a lifetime.
        if rtype != TYPE_OPT {
            min_ttl = Some(min_ttl.map_or(ttl, |min| min.min(ttl)));
        }

        // Addresses come from the answer section only.
        if index < ancount && rtype == qtype && pos + rdlength <= data.len() {
            let rdata = &data[pos..pos + rdlength];
            if rtype == TYPE_A && rdlength == 4 {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            } else if rtype == TYPE_AAAA && rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
        }

        pos += rdlength;
    }

    Ok(Answer {
        rcode,
        ips,
        ttl: min_ttl.unwrap_or(0),
    })
}

pub(super) fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
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
    fn parse_dns_response_too_short() {
        assert!(parse_dns_response(&[0u8; 5], 1).is_err());
    }

    /// mihomo compat: a reply without answers is an answer, not a failure —
    /// dns/util.go batchExchange only fails a reply for SERVFAIL / REFUSED.
    /// (This asserted an error before; the error made the server reply
    /// SERVFAIL to every NODATA.)
    #[test]
    fn parse_dns_response_no_answers() {
        // Minimal DNS response header with 0 answers.
        let data = vec![0u8; 12];
        // ancount = 0 (bytes 6-7 already zero).
        assert_eq!(
            parse_dns_response(&data, 1).unwrap(),
            Answer {
                rcode: 0,
                ips: vec![],
                ttl: 0
            }
        );
    }

    /// mihomo compat: dns/util.go putMsgToCache — a negative reply is cached
    /// for the smallest TTL among its records, i.e. the SOA in the authority
    /// section; the OPT record's TTL field is flags and does not count.
    #[test]
    fn parse_dns_response_negative_answer_keeps_rcode_and_soa_ttl() {
        let query = build_dns_query("nxdomain.example.com", TYPE_A);
        let soa = (6, 900, vec![0u8; 22]);
        let mut data = test_support::reply(&query, 3, &[], &[soa]);
        data[11] = 1; // one additional record: OPT, root name, TTL field 0
        data.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(
            parse_dns_response(&data, TYPE_A).unwrap(),
            Answer {
                rcode: 3,
                ips: vec![],
                ttl: 900
            }
        );
    }

    /// Every address of the answer is kept, in order, with the smallest TTL
    /// of the reply (dns/util.go minimalTTL) — the CNAME's included.
    #[test]
    fn parse_dns_response_collects_every_address() {
        let query = build_dns_query("www.example.com", TYPE_A);
        let data = test_support::reply(
            &query,
            0,
            &[
                (5, 300, vec![0xc0, 0x0c]),
                (TYPE_A, 60, vec![203, 0, 113, 1]),
                (TYPE_A, 120, vec![203, 0, 113, 2]),
            ],
            &[],
        );

        assert_eq!(
            parse_dns_response(&data, TYPE_A).unwrap(),
            Answer {
                rcode: 0,
                ips: vec![
                    "203.0.113.1".parse().unwrap(),
                    "203.0.113.2".parse().unwrap()
                ],
                ttl: 60
            }
        );
    }

    /// mihomo compat: dns/util.go batchExchange — SERVFAIL and REFUSED fail
    /// the server that sent them; an NXDOMAIN from another one wins the race.
    #[tokio::test]
    async fn race_relays_nxdomain_and_fails_on_servfail_and_refused() {
        let servfail = test_support::nameserver(|q| test_support::reply(q, 2, &[], &[])).await;
        let refused = test_support::nameserver(|q| test_support::reply(q, 5, &[], &[])).await;
        let nxdomain = test_support::nameserver(|q| {
            test_support::reply(q, 3, &[], &[(6, 600, vec![0u8; 22])])
        })
        .await;

        let answer = batch_resolve(
            "missing.example.com",
            &[servfail.clone(), refused.clone(), nxdomain],
            TYPE_A,
        )
        .await
        .unwrap();
        assert_eq!(
            answer,
            Answer {
                rcode: 3,
                ips: vec![],
                ttl: 600
            }
        );

        let err = batch_resolve("missing.example.com", &[servfail], TYPE_A)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "all DNS requests failed, first error: server failure: SERVFAIL"
        );
        let err = batch_resolve("missing.example.com", &[refused], TYPE_A)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "all DNS requests failed, first error: server failure: REFUSED"
        );
    }

    /// mihomo compat: resolver.go ipExchange — without fallback servers the
    /// main answer is returned directly; the fallback filters are not
    /// consulted, so nothing is "triggered" for a public non-CN address.
    #[tokio::test]
    async fn no_fallback_servers_means_no_fallback_filtering() {
        #[derive(Clone, Default)]
        struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Logs {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logs = Logs::default();
        let writer = logs.clone();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(move || writer.clone())
                .finish(),
        );

        let main = test_support::nameserver(|q| {
            test_support::reply(q, 0, &[(TYPE_A, 60, vec![8, 8, 8, 8])], &[])
        })
        .await;
        let config = DnsConfig {
            nameserver: vec![main],
            ..Default::default()
        };
        let answer = resolve_qtype("example.com", &config, TYPE_A).await.unwrap();
        assert_eq!(answer.ips, ["8.8.8.8".parse::<IpAddr>().unwrap()]);

        let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(!logs.contains("fallback"), "unexpected log: {logs}");
    }

    /// mihomo compat: dns/client.go — a truncated UDP reply (TC=1) is asked
    /// again over TCP, and the TCP reply is the answer.
    #[tokio::test]
    async fn truncated_udp_reply_is_retried_over_tcp() {
        let server = test_support::truncating_nameserver(|q| {
            test_support::reply(q, 0, &[(TYPE_A, 60, vec![203, 0, 113, 9])], &[])
        })
        .await;

        let answer = resolve_udp("big.example.com", &server, TYPE_A)
            .await
            .unwrap();
        assert_eq!(answer.ips, ["203.0.113.9".parse::<IpAddr>().unwrap()]);
    }
}

/// Canned nameservers for the resolver tests.
#[cfg(test)]
pub(super) mod test_support {
    /// A record owned by the question name: (type, TTL, RDATA).
    pub type Record = (u16, u32, Vec<u8>);

    /// The reply to `query` with the given header flags (the response code is
    /// their low nibble), answer records and authority records.
    pub fn reply(query: &[u8], flags: u16, answers: &[Record], authority: &[Record]) -> Vec<u8> {
        let question_end = super::skip_dns_name(query, 12).unwrap() + 4;
        let mut message = query[..2].to_vec();
        message.extend_from_slice(&(0x8000 | flags).to_be_bytes());
        message.extend_from_slice(&[0, 1]);
        message.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        message.extend_from_slice(&(authority.len() as u16).to_be_bytes());
        message.extend_from_slice(&[0, 0]);
        message.extend_from_slice(&query[12..question_end]);
        for (rtype, ttl, rdata) in answers.iter().chain(authority) {
            message.extend_from_slice(&[0xc0, 0x0c]);
            message.extend_from_slice(&rtype.to_be_bytes());
            message.extend_from_slice(&[0, 1]);
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            message.extend_from_slice(rdata);
        }
        message
    }

    /// Start a loopback UDP nameserver answering each query with
    /// `answer(query)`; returns its `ip:port`.
    pub async fn nameserver(answer: impl Fn(&[u8]) -> Vec<u8> + Send + 'static) -> String {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&answer(&buf[..n]), peer).await;
            }
        });
        addr
    }

    /// Start a loopback nameserver that truncates over UDP — its reply there
    /// is the TC bit and nothing else — and answers a query over TCP with
    /// `answer(query)`; returns its `ip:port`.
    pub async fn truncating_nameserver(
        answer: impl Fn(&[u8]) -> Vec<u8> + Send + 'static,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                let _ = udp.send_to(&reply(&buf[..n], 0x0200, &[], &[]), peer).await;
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).await.unwrap();
                let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                stream.read_exact(&mut query).await.unwrap();
                let reply = answer(&query);
                stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&reply).await.unwrap();
            }
        });
        addr.to_string()
    }
}
