pub mod cache;
pub mod fakeip;
pub mod upstream;

use anyhow::Result;
use dashmap::DashMap;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info};

use crate::config::DnsConfig;
use cache::DnsCache;
use fakeip::{FakeIpPool, FilterEntry};
use upstream::Answer;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;

type DomainCheckerFn = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Hands out the resolver of the running config.
///
/// mihomo compat: whatever serves DNS reads the process-wide resolver that
/// executor.go updateDNS replaces on every reload. A task that outlives a
/// reload must therefore ask for the resolver per query instead of keeping
/// the `Arc<DnsResolver>` it was started with: that one's fake-ip pool is
/// not the pool connections are looked up in any more.
pub type ResolverProvider = Arc<dyn Fn() -> Arc<DnsResolver> + Send + Sync>;

/// Entries the ip→host mapping holds (mihomo dns/enhancer.go NewEnhancer).
const HOST_MAPPING_SIZE: usize = 4096;

/// ip→host of the addresses answered to DNS clients.
///
/// mihomo compat: dns/enhancer.go — `lru.New(lru.WithSize(4096))`, an LRU
/// without an age limit: an entry lives until 4096 more recently used ones
/// push it out, however short the TTL of its record was.
#[derive(Clone, Default)]
struct HostMapping {
    /// Host and recency stamp per address.
    entries: HashMap<IpAddr, (String, u64)>,
    /// Addresses by recency stamp, least recently used first.
    recency: BTreeMap<u64, IpAddr>,
    stamp: u64,
}

impl HostMapping {
    /// Map `ip` to `host` as the most recently used entry, evicting the least
    /// recently used one beyond the size limit.
    fn set(&mut self, ip: IpAddr, host: &str) {
        self.stamp += 1;
        if let Some((_, old)) = self.entries.insert(ip, (host.to_string(), self.stamp)) {
            self.recency.remove(&old);
        }
        self.recency.insert(self.stamp, ip);
        if self.entries.len() > HOST_MAPPING_SIZE {
            if let Some((_, oldest)) = self.recency.pop_first() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// The host of `ip`; a hit becomes the most recently used entry.
    fn get(&mut self, ip: &IpAddr) -> Option<String> {
        let (host, stamp) = self.entries.get_mut(ip)?;
        self.recency.remove(stamp);
        self.stamp += 1;
        *stamp = self.stamp;
        self.recency.insert(self.stamp, *ip);
        Some(host.clone())
    }
}

pub struct DnsResolver {
    config: DnsConfig,
    cache: DnsCache,
    fakeip: Option<FakeIpPool>,
    hosts: std::collections::HashMap<String, IpAddr>,
    /// Geosite codes from fake-ip-filter (e.g. "geosite:cn" → "cn").
    fakeip_geosite_codes: Vec<String>,
    /// Callback to check if a domain matches a geosite code.
    /// Set after construction via `set_geosite_checker()`.
    geosite_checker: Option<DomainCheckerFn>,
    /// Rule-provider names from fake-ip-filter (e.g. "rule-set:oc-cn-domain"
    /// → "oc-cn-domain"). mihomo config.go parseFakeIPRules.
    fakeip_ruleset_names: Vec<String>,
    /// Callback to check if a domain matches a rule provider's domain rules.
    /// Set after construction via `set_ruleset_checker()`.
    ruleset_checker: Option<DomainCheckerFn>,
    /// Reverse IP→domain mapping for redir-host mode and traffic logging.
    /// Matches mihomo's dns/enhancer.go mapping LRU: it is populated ONLY from
    /// answers this resolver served to a DNS client (`serve_ip`, i.e. mihomo's
    /// withMapping/withHosts middleware) — never from the internal
    /// rule-matching resolutions in `resolve_real_ip`, which would map shared
    /// CDN addresses to the last domain that resolved to them.
    ip_to_host: parking_lot::Mutex<HostMapping>,
    /// Cache for proxy server hostname resolution (avoids DNS storm).
    /// Key: domain, Value: (resolved IP, expiry instant).
    /// TTL = 120 seconds — long enough to prevent storms, short enough to follow DNS changes.
    proxy_dns_cache: DashMap<String, (IpAddr, Instant)>,
    /// Per-domain singleflight for proxy server DNS to dedup concurrent queries.
    /// Key: domain, Value: mutex guarding the in-flight resolution.
    /// Entries are never removed — the key set is bounded by the proxy server
    /// hostnames in the config, so this is not a leak.
    proxy_dns_inflight: DashMap<String, Arc<TokioMutex<()>>>,
}

impl DnsResolver {
    pub async fn new(config: &DnsConfig) -> Result<Self> {
        Self::with_hosts(config, &std::collections::HashMap::new()).await
    }

    /// Create a new resolver with an explicit hosts map (from config.hosts).
    pub async fn with_hosts(
        config: &DnsConfig,
        hosts_map: &std::collections::HashMap<String, String>,
    ) -> Result<Self> {
        let cache = DnsCache::new(config.cache_max_size as usize);

        let fakeip = if config.enable && config.enhanced_mode == "fake-ip" {
            Some(FakeIpPool::new(
                &config.fake_ip_range,
                &config.fake_ip_filter,
                &config.fake_ip_filter_mode,
            )?)
        } else {
            None
        };

        // Parse hosts map: string → IpAddr, skip entries that don't parse
        let hosts = hosts_map
            .iter()
            .filter_map(|(domain, ip_str)| {
                ip_str
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| (domain.to_lowercase(), ip))
            })
            .collect();

        // Extract the geosite: and rule-set: entries from fake-ip-filter for
        // bypass checking (the pool compiles the domain patterns).
        // e.g. "geosite:cn" means all domains in the GeoSite "cn" group should
        // bypass FakeIP and get real IP resolution instead;
        // "rule-set:oc-cn-domain" matches the domain rules of that rule
        // provider (mihomo config.go parseDomain).
        let mut fakeip_geosite_codes = Vec::new();
        let mut fakeip_ruleset_names = Vec::new();
        for entry in &config.fake_ip_filter {
            match FilterEntry::parse(entry) {
                FilterEntry::Geosite(codes) => {
                    fakeip_geosite_codes.extend(codes.iter().map(|code| code.to_lowercase()))
                }
                FilterEntry::RuleSet(names) => {
                    fakeip_ruleset_names.extend(names.iter().map(|name| name.to_string()))
                }
                FilterEntry::Domain(_) => {}
            }
        }
        if !fakeip_geosite_codes.is_empty() {
            info!("FakeIP bypass geosite codes: {:?}", fakeip_geosite_codes);
        }
        if !fakeip_ruleset_names.is_empty() {
            info!("FakeIP bypass rule-sets: {:?}", fakeip_ruleset_names);
        }

        Ok(Self {
            config: config.clone(),
            cache,
            fakeip,
            hosts,
            fakeip_geosite_codes,
            geosite_checker: None,
            fakeip_ruleset_names,
            ruleset_checker: None,
            ip_to_host: parking_lot::Mutex::default(),
            proxy_dns_cache: DashMap::new(),
            proxy_dns_inflight: DashMap::new(),
        })
    }

    /// Set a geosite checker function for fake-ip-filter geosite bypass.
    /// Called after construction once the RuleEngine (with GeoSite.dat) is built.
    pub fn set_geosite_checker<F>(&mut self, checker: F)
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.geosite_checker = Some(Arc::new(checker));
    }

    /// Set a rule-set checker function for fake-ip-filter `rule-set:` bypass.
    /// Called after construction once the RuleEngine (with its rule providers)
    /// is built. The checker receives (domain, provider_name).
    pub fn set_ruleset_checker<F>(&mut self, checker: F)
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.ruleset_checker = Some(Arc::new(checker));
    }

    /// Rule-provider names referenced by `rule-set:` fake-ip-filter entries.
    /// Used at wiring time to report references to providers that never loaded
    /// (mihomo fails the config load in that case — config.go:1604).
    pub fn fakeip_ruleset_names(&self) -> &[String] {
        &self.fakeip_ruleset_names
    }

    /// Check if a domain should bypass FakeIP (get real IP instead).
    ///
    /// mihomo compat: the filter-mode applies to the WHOLE matcher set —
    /// pattern entries, `geosite:` and `rule-set:` alike (config.go
    /// parseFakeIPRules builds one host matcher list; skipper.go inverts it
    /// for whitelist mode). Blacklist: matched domains bypass; whitelist:
    /// only matched domains get fake IPs, everything else bypasses.
    fn should_bypass_fakeip(&self, domain: &str) -> bool {
        let Some(ref pool) = self.fakeip else {
            return false;
        };

        // Pattern-based filter (*.lan, +.qq.com, etc.)
        let mut matched = pool.filter_matches(domain);

        // geosite:-based filter entries (e.g. "geosite:cn")
        if !matched && !self.fakeip_geosite_codes.is_empty() {
            if let Some(ref checker) = self.geosite_checker {
                matched = self
                    .fakeip_geosite_codes
                    .iter()
                    .any(|code| checker(domain, code));
            }
        }

        // rule-set:-based filter entries (e.g. "rule-set:oc-cn-domain")
        if !matched && !self.fakeip_ruleset_names.is_empty() {
            if let Some(ref checker) = self.ruleset_checker {
                matched = self
                    .fakeip_ruleset_names
                    .iter()
                    .any(|name| checker(domain, name));
            }
        }

        if pool.is_whitelist() {
            !matched
        } else {
            matched
        }
    }

    /// Answer an A (1) or AAAA (28) question the way the DNS server does. In
    /// fake-ip mode an A question gets a fake IP; in redir-host mode, and for
    /// the names the fake-ip filter skips, upstream DNS is queried.
    ///
    /// mihomo compat: dns/middleware.go newHandler — withHosts, withFakeIP,
    /// withMapping and withResolver, composed in that order. All real
    /// addresses answered are recorded in the ip_to_host mapping for reverse
    /// lookups (withMapping).
    ///
    /// The answer's TTL is the upstream record's TTL, counted down on a cache
    /// hit (resolver.go ExchangeContext → updateMsgTTL); only fake-ip answers
    /// get a synthetic TTL (`fake-ip-ttl`, default 1) and hosts entries get 10
    /// (middleware.go withHosts). Advertising a fixed TTL for real answers
    /// makes clients pin a CDN address far longer than the CDN intends, so
    /// they keep dialing an edge that has since stopped serving the name
    /// (connection reset / certificate for another host).
    async fn serve_ip(&self, domain: &str, qtype: u16) -> Result<Answer> {
        // Check hosts map first (highest priority, like /etc/hosts)
        if let Some(ip) = self.host_ip(domain) {
            // mihomo compat: withHosts() answers both address families from a
            // hosts entry — with nothing for the family it has no address of —
            // and also records into the mapping.
            let ips: Vec<IpAddr> = Some(ip)
                .filter(|ip| ip.is_ipv4() == (qtype == TYPE_A))
                .into_iter()
                .collect();
            for ip in &ips {
                self.record_ip_mapping(*ip, domain);
            }
            return Ok(Answer {
                rcode: 0,
                ips,
                ttl: 10,
            });
        }

        // FakeIP mode: assign a fake IP — unless the domain is in the bypass filter.
        // Bypassed domains (e.g. *.lan, geosite:cn, NTP servers, music services)
        // get resolved to real IPs via upstream DNS instead.
        //
        // mihomo compat: middleware.go newHandler composes withFakeIP BEFORE
        // withResolver, so the fake-ip pool is consulted ahead of the resolver's
        // answer cache and is the only authority for non-bypassed domains. The
        // cache lookup must NOT run first: `resolve_real_ip` (the rule-matching
        // path, tunnel.go match()) caches REAL IPs under the same domain key,
        // and a cache-first order hands those real IPs back to DNS clients —
        // fake-ip silently stops applying to every domain that ever matched an
        // IP rule, and the client then caches a CDN address for the full TTL.
        if let Some(ref pool) = self.fakeip {
            if !self.should_bypass_fakeip(domain) {
                // mihomo compat: FakeIP allocations are NOT cached in the DNS
                // cache and NOT recorded in ip_to_host (withFakeIP answers
                // before withMapping runs). They are already stored in the
                // FakeIP pool, the single source of truth for its
                // domain <-> IP mapping. An AAAA question has no pool to draw
                // from (no fake-ip-range6: `fakePool6 == nil`) and gets an
                // empty answer.
                if qtype != TYPE_A {
                    return Ok(Answer::empty());
                }
                return Ok(Answer {
                    rcode: 0,
                    ips: vec![pool.allocate(domain)],
                    ttl: FAKEIP_TTL,
                });
            }
        }

        // mihomo compat: middleware.go withResolver — "return a empty AAAA msg
        // when ipv6 disabled".
        if qtype == TYPE_AAAA && !self.config.ipv6 {
            return Ok(Answer::empty());
        }

        // Filtered domain or redir-host mode: the resolver's answer.
        let answer = self.exchange(domain, qtype).await?;
        // mihomo compat: withMapping() records every address answered to a
        // client, whether the resolver had the answer cached or not.
        for ip in &answer.ips {
            self.record_ip_mapping(*ip, domain);
        }
        Ok(answer)
    }

    /// Put a question to the resolver itself — its answer cache and its
    /// nameservers, past hosts and fake-ip — and return the raw reply.
    ///
    /// mihomo compat: hub/route/dns.go queryDNS, which exchanges the message
    /// with `resolver.DefaultResolver`.
    pub async fn query(&self, domain: &str, qtype: u16) -> Result<Vec<u8>> {
        match qtype {
            TYPE_A | TYPE_AAAA => {
                let answer = self.exchange(domain, qtype).await?;
                let query = Query {
                    id: 0,
                    domain: domain.to_string(),
                    qtype,
                    edns0: None,
                };
                Ok(build_dns_response(&query, &answer, None))
            }
            _ => {
                let query = upstream::build_dns_query(domain, qtype);
                self.forward_raw_query(&query, true).await
            }
        }
    }

    /// The `hosts` entry for a name, if it has one.
    fn host_ip(&self, domain: &str) -> Option<IpAddr> {
        if self.hosts.is_empty() {
            return None;
        }
        self.hosts.get(&domain.to_lowercase()).copied()
    }

    /// Answer an A/AAAA question from the resolver proper: the answer cache,
    /// then the upstream nameservers, whose reply is cached — an NXDOMAIN or
    /// empty one just like addresses.
    ///
    /// mihomo compat: dns/resolver.go ExchangeContext. A reply is cached for
    /// the smallest TTL among its records (dns/util.go putMsgToCache), so a
    /// negative answer lives as long as the SOA it came with.
    async fn exchange(&self, domain: &str, qtype: u16) -> Result<Answer> {
        let key: Cow<str> = match qtype {
            TYPE_AAAA => format!("AAAA:{domain}").into(),
            _ => domain.into(),
        };
        if let Some(answer) = self.cache.get(&key) {
            return Ok(answer);
        }

        // mihomo compat: resolver.go — nameserver-policy is consulted before
        // the main/fallback tiers for every query; a hit is used directly.
        let answer = match self.policy_servers(&self.config.nameserver_policy, domain) {
            Some(servers) => upstream::resolve_via(domain, &servers, qtype).await?,
            None => upstream::resolve_qtype(domain, &self.config, qtype).await?,
        };
        self.cache.insert(key.into_owned(), &answer);
        Ok(answer)
    }

    /// Resolve a domain to a REAL IP, never a FakeIP.
    ///
    /// mihomo compat: tunnel.go `match()` calls `resolver.ResolveIP()` on
    /// demand when a rule needs the destination IP (GEOIP / IP-CIDR /
    /// IP-SUFFIX / IP-ASN without `no-resolve`) but the connection only carries
    /// a domain — `preHandleMetadata` blanked the FakeIP from `dst_ip`. Without
    /// this, `GEOIP,CN,DIRECT` can never match domain traffic under fake-ip and
    /// domestic connections leak through the proxy catch-all.
    ///
    /// Mirrors `serve_ip()` minus the FakeIP-allocate branch: hosts → DNS cache
    /// → upstream (with fallback + GeoIP anti-poison), caching the real result.
    /// Used solely for rule matching; the dial path still uses the domain.
    pub async fn resolve_real_ip(&self, domain: &str) -> Result<IpAddr> {
        // IP literal — return as-is.
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Hosts map first (highest priority, like /etc/hosts).
        if let Some(ip) = self.host_ip(domain) {
            return Ok(ip);
        }

        // The resolver's answer: DNS cache, then upstream for a real IP (full
        // fallback + anti-poison pipeline).
        //
        // mihomo compat: this mirrors `resolver.ResolveIP` called from tunnel.go
        // match(), which goes through the Resolver's own message cache and never
        // reaches the enhancer mapping — only the DNS *server* middleware
        // (withMapping / withHosts) populates ip→host. Recording here would map
        // every CDN address to whichever domain resolved to it last, and
        // preHandleMetadata would then rewrite an unrelated connection's host to
        // that domain (wrong SNI → wrong certificate).
        self.exchange(domain, TYPE_A).await?.first_ip(domain)
    }

    /// Reverse-lookup: given an IP, return the original domain.
    ///
    /// mihomo compat: matches enhancer.go FindHostByIP() — checks FakeIP pool
    /// first (authoritative for FakeIP range), then the general ip_to_host
    /// mapping (for redir-host mode + real IP logging).
    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<String> {
        // Check FakeIP pool first (authoritative for FakeIP range)
        if let Some(ref pool) = self.fakeip {
            if let Some(domain) = pool.lookup_domain(ip) {
                return Some(domain);
            }
        }
        // Check the general IP→host mapping (for redir-host mode + logging)
        self.ip_to_host.lock().get(ip)
    }

    /// mihomo compat: withMapping() in dns/middleware.go.
    fn record_ip_mapping(&self, ip: IpAddr, domain: &str) {
        // mihomo compat: withMapping skips answers that are not global unicast
        // (`if !ip.IsGlobalUnicast() { continue }`) — an ad-blocking upstream
        // that answers 0.0.0.0/127.0.0.1 must not claim the reverse mapping for
        // those addresses and rewrite unrelated connections' hosts.
        if !is_global_unicast(&ip) {
            return;
        }
        self.ip_to_host.lock().set(ip, domain);
    }

    /// Manually insert an IP→domain mapping.
    /// mihomo compat: sniffer's InsertHostByIP hook; not yet wired.
    #[allow(dead_code)]
    pub fn insert_host_by_ip(&self, ip: IpAddr, host: &str) {
        self.record_ip_mapping(ip, host);
    }

    /// Query upstream DNS servers for a real IP.
    /// Returns only the first address (the others and the TTL are discarded).
    pub async fn query_upstream(&self, domain: &str) -> Result<IpAddr> {
        upstream::resolve(domain, &self.config)
            .await?
            .first_ip(domain)
    }

    /// Whether fake-ip mode is active.
    pub fn fakeip_enabled(&self) -> bool {
        self.fakeip.is_some()
    }

    /// Forward a raw DNS query (non-A/AAAA types) to the first plain-UDP main
    /// nameserver and return the raw response.
    /// mihomo compat: middleware.go withResolver relays other query types to
    /// the upstream unchanged.
    ///
    /// A truncated reply is asked again over TCP (dns/client.go) when the
    /// client came over TCP itself (`tcp_client`). A UDP client gets the
    /// truncated reply as it is: it could not take the full one either, and
    /// its TC bit sends the client to TCP.
    pub async fn forward_raw_query(&self, query: &[u8], tcp_client: bool) -> Result<Vec<u8>> {
        let server = upstream::plain_udp_server(&self.config)
            .ok_or_else(|| anyhow::anyhow!("no plain-UDP nameserver for passthrough"))?;
        let response = upstream::exchange_udp(server, query).await?;
        if tcp_client && upstream::is_truncated(&response) {
            return upstream::exchange_tcp(server, query).await;
        }
        Ok(response)
    }

    /// Find the servers a nameserver policy assigns to a domain, in config
    /// order.
    /// mihomo compat: config.go parseNameServerPolicy — keys may be
    /// comma-separated lists and support `geosite:`/`rule-set:` prefixes
    /// (checked via the wired rule-engine checkers) plus domain patterns
    /// (exact / `+.` / `*.`).
    fn policy_servers(&self, policy: &serde_yaml::Mapping, domain: &str) -> Option<Vec<String>> {
        if policy.is_empty() {
            return None;
        }
        upstream::find_nameserver_policy(domain, policy, |pattern, domain| {
            if let Some(code) = pattern.strip_prefix("geosite:") {
                self.geosite_checker
                    .as_ref()
                    .is_some_and(|c| c(domain, code))
            } else if let Some(name) = pattern.strip_prefix("rule-set:") {
                self.ruleset_checker
                    .as_ref()
                    .is_some_and(|c| c(domain, name))
            } else {
                upstream::domain_pattern_match(pattern, domain)
            }
        })
    }

    /// Look up `domain` in the proxy-DNS cache. Returns `Some(Ok)` on a live
    /// positive entry, `Some(Err)` on a live negative entry, `None` on a miss
    /// (stale entries are removed). `label` distinguishes the debug logs.
    fn proxy_dns_cache_lookup(&self, domain: &str, label: &str) -> Option<Result<IpAddr>> {
        const PROXY_DNS_TTL_OK: Duration = Duration::from_secs(120);
        const PROXY_DNS_TTL_FAIL: Duration = Duration::from_secs(10);

        let entry = self.proxy_dns_cache.get(domain)?;
        let (ip, created) = *entry;
        let ttl = if ip.is_unspecified() {
            PROXY_DNS_TTL_FAIL // negative cache entry
        } else {
            PROXY_DNS_TTL_OK
        };
        if created.elapsed() < ttl {
            if ip.is_unspecified() {
                return Some(Err(anyhow::anyhow!(
                    "DNS resolution for proxy server '{domain}' failed (cached negative result)"
                )));
            }
            debug!("DNS proxy-server cache hit{}: {} -> {}", label, domain, ip);
            return Some(Ok(ip));
        }
        // Expired — remove stale entry
        drop(entry);
        self.proxy_dns_cache.remove(domain);
        None
    }

    /// Resolve a proxy server hostname.
    ///
    /// mihomo compat: hub/executor/executor.go updateDNS — the resolver for
    /// proxy server hosts is the dedicated one only when
    /// `proxy-server-nameserver` is configured, and that one knows nothing
    /// but those servers and `proxy-server-nameserver-policy` (dns/resolver.go
    /// NewResolver): no fall-through to other nameservers. Otherwise it is
    /// the main resolver — `nameserver-policy`, `nameserver`, `fallback` —
    /// like any other lookup. `default-nameserver` is never asked: it only
    /// bootstraps the hostnames of nameservers. Whatever the nameservers
    /// answer is used as is.
    ///
    /// Results are cached for 120s (success) or 10s (failure) and concurrent
    /// queries for the same domain are deduplicated via per-domain mutex to
    /// prevent DNS storms during health checks / retries.
    pub async fn resolve_proxy_server(&self, domain: &str) -> Result<IpAddr> {
        // If it's already an IP literal, just parse it
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Check cache first
        if let Some(result) = self.proxy_dns_cache_lookup(domain, "") {
            return result;
        }

        // Singleflight: acquire per-domain mutex to dedup concurrent queries.
        // Only one task actually queries upstream; others wait for the result.
        let mutex = self
            .proxy_dns_inflight
            .entry(domain.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();

        let _guard = mutex.lock().await;

        // Re-check cache after acquiring lock (another task may have populated it)
        if let Some(result) = self.proxy_dns_cache_lookup(domain, " (after dedup)") {
            return result;
        }

        // Actually resolve
        let result = if self.config.proxy_server_nameserver.is_empty() {
            self.resolve_real_ip(domain).await
        } else {
            self.resolve_via_proxy_nameservers(domain).await
        };

        match &result {
            Ok(ip) => {
                // Cache successful result (120s)
                self.proxy_dns_cache
                    .insert(domain.to_string(), (*ip, Instant::now()));
            }
            Err(_) => {
                // Negative cache (10s) — prevents repeated failed queries
                // Uses 0.0.0.0 as sentinel for "failed"
                self.proxy_dns_cache.insert(
                    domain.to_string(),
                    (IpAddr::V4(Ipv4Addr::UNSPECIFIED), Instant::now()),
                );
            }
        }

        result
    }

    /// Resolve through the dedicated proxy-server resolver: `hosts`, then the
    /// `proxy-server-nameserver-policy` servers for the name or, without a
    /// policy hit, `proxy-server-nameserver`.
    async fn resolve_via_proxy_nameservers(&self, domain: &str) -> Result<IpAddr> {
        // mihomo compat: component/resolver/resolver.go LookupIPWithResolver
        // searches the hosts before it asks whichever resolver it was given.
        if let Some(ip) = self.host_ip(domain) {
            return Ok(ip);
        }
        let servers = self
            .policy_servers(&self.config.proxy_server_nameserver_policy, domain)
            .unwrap_or_else(|| self.config.proxy_server_nameserver.clone());
        upstream::resolve_via(domain, &servers, TYPE_A)
            .await?
            .first_ip(domain)
    }

    /// Check if an IP is a fake IP.
    /// mihomo compat: enhancer.go IsFakeIP — the gateway (the TUN device
    /// address) and the broadcast address of the range are NOT fake IPs.
    pub fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        if let Some(ref pool) = self.fakeip {
            return pool.is_fake_ip(ip);
        }
        false
    }

    /// Flush the DNS cache and IP→domain mapping.
    pub fn flush_cache(&self) {
        self.cache.clear();
        self.flush_mapping();
    }

    /// Flush the IP→domain reverse mapping.
    /// mihomo compat: clearing the mapping alongside the cache ensures
    /// stale reverse lookups don't persist after a cache flush.
    fn flush_mapping(&self) {
        *self.ip_to_host.lock() = HostMapping::default();
    }

    /// Flush the FakeIP pool.
    pub fn flush_fakeip(&self) {
        if let Some(ref pool) = self.fakeip {
            pool.clear();
        }
    }

    /// Carry cached state over from the previous resolver on config reload.
    ///
    /// mihomo compat: dns/enhancer.go `PatchFrom` (called from executor.go
    /// updateDNS — "reuse cache of old host mapper") clones the fake-ip pool
    /// store and the ip→host mapping into the new enhancer so client-cached
    /// fake IPs stay valid across reloads instead of being reassigned to
    /// other domains from offset zero.
    pub fn patch_from(&self, old: &DnsResolver) {
        if let (Some(new_pool), Some(old_pool)) = (self.fakeip.as_ref(), old.fakeip.as_ref()) {
            new_pool.clone_from(old_pool);
        }
        // LruCache.CloneTo overwrites the target mapping wholesale.
        let mapping = old.ip_to_host.lock().clone();
        *self.ip_to_host.lock() = mapping;
    }

    /// Save FakeIP mappings to disk.
    pub fn save_fakeip(&self, path: &std::path::Path) -> Result<()> {
        if let Some(ref pool) = self.fakeip {
            pool.save(path)?;
        }
        Ok(())
    }

    /// Load FakeIP mappings from disk.
    pub fn load_fakeip(&self, path: &std::path::Path) -> Result<()> {
        if let Some(ref pool) = self.fakeip {
            pool.load(path)?;
        }
        Ok(())
    }
}

/// The largest reply to a hijacked UDP query (mihomo
/// `resolver.SafeDnsPacketSize`: "safe size which is 1232 from
/// https://dnsflagday.net/2020/, so 2048 is enough").
pub const SAFE_DNS_PACKET_SIZE: usize = 2048;

/// The UDP payload size our own EDNS0 OPT record advertises (mihomo
/// dns/service.go): the fragmentation-safe one of https://dnsflagday.net/2020/.
const EDNS0_UDP_SIZE: u16 = 1232;

/// Process a raw DNS query packet and produce a raw DNS response packet.
///
/// Shared by the embedded UDP/TCP DNS servers and the TUN dns-hijack path
/// (mihomo `resolver.RelayDnsPacket`): a hijacked query is answered by the
/// internal resolver rather than being forwarded to its original destination.
/// `udp_size_limit` is `None` for a query that came over TCP; over UDP the
/// reply is cut down to the smaller of it and the size the client advertises.
/// Returns `None` if the query can't be parsed.
pub async fn process_dns_query(
    data: &[u8],
    resolver: &DnsResolver,
    udp_size_limit: Option<usize>,
) -> Option<Vec<u8>> {
    let query = parse_dns_query(data)?;
    let domain = query.domain.as_str();

    let answer = match query.qtype {
        TYPE_A | TYPE_AAAA => resolver.serve_ip(domain, query.qtype).await,
        // mihomo compat: middleware.go withFakeIP — SVCB/HTTPS queries get an
        // empty answer under fake-ip so clients fall back to A/AAAA.
        TYPE_SVCB | TYPE_HTTPS
            if resolver.fakeip_enabled() && !resolver.should_bypass_fakeip(domain) =>
        {
            Ok(Answer::empty())
        }
        // mihomo compat: every other query type (TXT/SRV/MX/PTR/...) passes
        // through to the upstream unchanged (middleware.go withResolver →
        // raw exchange) instead of being answered with a bogus A record.
        _ => {
            let tcp_client = udp_size_limit.is_none();
            return Some(match resolver.forward_raw_query(data, tcp_client).await {
                Ok(mut response) => {
                    if let Some((_, dnssec_ok)) = query.edns0 {
                        if edns0(&response).is_none() {
                            append_edns0(&mut response, dnssec_ok);
                        }
                    }
                    response
                }
                Err(e) => {
                    debug!(
                        "DNS passthrough failed for {} (type {}): {}",
                        domain, query.qtype, e
                    );
                    build_dns_servfail(&query)
                }
            });
        }
    };

    Some(match answer {
        Ok(answer) => build_dns_response(&query, &answer, udp_size_limit),
        Err(e) => {
            debug!("DNS resolve failed for {}: {}", domain, e);
            build_dns_servfail(&query)
        }
    })
}

/// The resolver a listener answers from: read for every query and replaced on
/// reload, so replies always come from the running config's resolver and its
/// fake-ip pool.
type Service = Arc<parking_lot::RwLock<Arc<DnsResolver>>>;

/// The embedded DNS listener (mihomo dns/server.go `server` and `address`).
struct Listener {
    address: String,
    service: Service,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// The listener of the running config, if it has one.
static SERVER: TokioMutex<Option<Listener>> = TokioMutex::const_new(None);

/// Start, re-bind or stop the DNS listener to match `config`, answering from
/// `resolver` — the resolver built from that config.
///
/// mihomo compat: hub/executor/executor.go updateDNS → dns/server.go
/// ReCreateServer, at boot and on every reload.
pub async fn recreate_server(config: &DnsConfig, resolver: Arc<DnsResolver>) {
    let (addr, service) = if config.enable {
        (config.listen.as_str(), Some(resolver))
    } else {
        ("", None)
    };
    recreate_listener(&mut *SERVER.lock().await, addr, service).await;
}

/// mihomo compat: dns/server.go ReCreateServer — an unchanged address keeps
/// the sockets and only swaps the resolver in (`SetService`); anything else
/// stops the listener and, given an address and a resolver, binds anew.
async fn recreate_listener(
    server: &mut Option<Listener>,
    addr: &str,
    service: Option<Arc<DnsResolver>>,
) {
    if let (Some(running), Some(service)) = (server.as_ref(), service.as_ref()) {
        if running.address == addr {
            *running.service.write() = service.clone();
            return;
        }
    }

    if let Some(running) = server.take() {
        for task in running.tasks {
            task.abort();
            // A socket closes with its task: wait, so that a re-bind of the
            // same port finds it free.
            let _ = task.await;
        }
    }

    let Some(service) = service else {
        return;
    };
    if addr.is_empty() {
        return;
    }
    let addrs = match listen_addrs(addr) {
        Ok(addrs) => addrs,
        Err(e) => {
            error!("Start DNS server error: {}", e);
            return;
        }
    };
    if addrs.is_empty() {
        return;
    }

    let service: Service = Arc::new(parking_lot::RwLock::new(service));
    let mut tasks = Vec::new();
    match UdpSocket::bind(addrs.as_slice()).await {
        Ok(socket) => {
            if let Ok(local) = socket.local_addr() {
                info!("DNS server(UDP) listening at: {}", local);
            }
            tasks.push(tokio::spawn(run_dns_udp_server(socket, service.clone())));
        }
        Err(e) => error!("Start DNS server(UDP) error: {}", e),
    }
    match TcpListener::bind(addrs.as_slice()).await {
        Ok(listener) => {
            if let Ok(local) = listener.local_addr() {
                info!("DNS server(TCP) listening at: {}", local);
            }
            tasks.push(tokio::spawn(run_dns_tcp_server(listener, service.clone())));
        }
        Err(e) => error!("Start DNS server(TCP) error: {}", e),
    }
    *server = Some(Listener {
        address: addr.to_string(),
        service,
        tasks,
    });
}

/// The socket addresses to bind for `dns.listen`, in order of preference;
/// none for port 0.
///
/// mihomo compat: dns/server.go ReCreateServer listens on nothing for port
/// "0", and Go's listener takes a host-less address (":1053") for every
/// address of the system: the dual-stack wildcard, or the IPv4 one where IPv6
/// is unavailable.
fn listen_addrs(addr: &str) -> Result<Vec<SocketAddr>> {
    let addrs = match addr.strip_prefix(':') {
        Some(port) => {
            let port: u16 = port
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid dns.listen address {addr}: {e}"))?;
            vec![
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            ]
        }
        None => vec![addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid dns.listen address {addr}: {e}"))?],
    };
    Ok(addrs.into_iter().filter(|addr| addr.port() != 0).collect())
}

/// DNS-over-UDP server: answers each datagram in its own task.
async fn run_dns_udp_server(socket: UdpSocket, service: Service) {
    // Replies come back through a channel so that this task alone holds the
    // socket: stopping the listener releases the port at once, whatever
    // queries are still in flight.
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(64);
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (n, src) = match received {
                    Ok(v) => v,
                    Err(e) => {
                        error!("DNS UDP recv error: {}", e);
                        continue;
                    }
                };

                let data = buf[..n].to_vec();
                let resolver = service.read().clone();
                let reply_tx = reply_tx.clone();

                tokio::spawn(async move {
                    // mihomo compat: server.go ServeDNS — the reply is fitted
                    // into the client's advertised buffer size, nothing less.
                    match process_dns_query(&data, &resolver, Some(usize::MAX)).await {
                        Some(response) => {
                            let _ = reply_tx.send((response, src)).await;
                        }
                        None => {
                            debug!("Failed to parse DNS query (UDP)");
                        }
                    }
                });
            }
            Some((response, src)) = reply_rx.recv() => {
                let _ = socket.send_to(&response, src).await;
            }
        }
    }
}

/// DNS-over-TCP server: accepts connections and handles DNS queries with
/// 2-byte length prefix framing (RFC 1035 section 4.2.2).
async fn run_dns_tcp_server(listener: TcpListener, service: Service) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("DNS TCP accept error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        let service = service.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dns_tcp_connection(stream, &service).await {
                debug!("DNS TCP connection from {} error: {}", peer, e);
            }
        });
    }
}

/// Handle a single DNS-over-TCP connection.
///
/// DNS over TCP uses a 2-byte big-endian length prefix before each message.
/// A single TCP connection can carry multiple queries (pipelining).
async fn handle_dns_tcp_connection(
    mut stream: tokio::net::TcpStream,
    service: &Service,
) -> Result<()> {
    loop {
        // Read the 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed the connection
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            return Ok(()); // Invalid length, close connection
        }

        // Read the DNS message
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        // Process the query — the connection may outlive a reload, so with
        // the resolver of the moment.
        let resolver = service.read().clone();
        let response = match process_dns_query(&msg_buf, &resolver, None).await {
            Some(response) => response,
            None => {
                debug!("Failed to parse DNS query (TCP)");
                continue;
            }
        };

        // Write 2-byte length prefix + response
        let resp_len = (response.len() as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
    }
}

/// The parts of a client query its reply is built from.
struct Query {
    id: u16,
    domain: String,
    qtype: u16,
    /// The client's EDNS0 OPT record, if it sent one: (UDP payload size, DO bit).
    edns0: Option<(u16, bool)>,
}

/// Minimal DNS query parser (extracts question domain and type, and EDNS0).
fn parse_dns_query(data: &[u8]) -> Option<Query> {
    if data.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);

    // Parse question section
    let mut pos = 12;
    let mut domain_parts = Vec::new();

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > data.len() {
            return None;
        }
        domain_parts.push(String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]).to_string());
        pos += 1 + len;
    }

    if pos + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let domain = domain_parts.join(".");

    Some(Query {
        id,
        domain,
        qtype,
        edns0: edns0(data),
    })
}

/// The EDNS0 OPT record of a DNS message, if it has one: (UDP payload size,
/// DO bit).
///
/// mihomo compat: miekg/dns Msg.IsEdns0 — any OPT record in the additional
/// section will do.
fn edns0(message: &[u8]) -> Option<(u16, bool)> {
    if message.len() < 12 {
        return None;
    }
    let count = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]) as usize;

    let mut pos = 12;
    for _ in 0..count(4) {
        pos = upstream::skip_dns_name(message, pos).ok()? + 4;
    }

    let additional_from = count(6) + count(8);
    let mut opt = None;
    for index in 0..additional_from + count(10) {
        let Ok(fixed) = upstream::skip_dns_name(message, pos) else {
            break;
        };
        let Some(header) = message.get(fixed..fixed + 10) else {
            break;
        };
        // An OPT record keeps the payload size in CLASS and the DO bit on top
        // of the third TTL byte (RFC 6891).
        if index >= additional_from && u16::from_be_bytes([header[0], header[1]]) == TYPE_OPT {
            opt = Some((
                u16::from_be_bytes([header[2], header[3]]),
                header[6] & 0x80 != 0,
            ));
        }
        pos = fixed + 10 + u16::from_be_bytes([header[8], header[9]]) as usize;
    }
    opt
}

/// Append our own EDNS0 OPT record to a reply.
///
/// mihomo compat: dns/service.go ServeMsg — "if the client asked with an OPT,
/// reply with our own OPT": `r.SetEdns0(1232, reqOpt.Do())` on any reply that
/// does not carry one. OPT is a per-hop pseudo-record (RFC 6891).
fn append_edns0(reply: &mut Vec<u8>, dnssec_ok: bool) {
    reply.push(0); // Root name
    reply.extend_from_slice(&TYPE_OPT.to_be_bytes());
    reply.extend_from_slice(&EDNS0_UDP_SIZE.to_be_bytes()); // CLASS: payload size
    reply.extend_from_slice(&[0, 0, if dnssec_ok { 0x80 } else { 0 }, 0]); // TTL: flags
    reply.extend_from_slice(&[0, 0]); // No options
    let additional = u16::from_be_bytes([reply[10], reply[11]]) + 1;
    reply[10..12].copy_from_slice(&additional.to_be_bytes());
}

/// mihomo compat: FakeIP responses use TTL=1.
const FAKEIP_TTL: u32 = 1;

/// mihomo compat: Go's `netip.Addr.IsGlobalUnicast` — everything except the
/// unspecified address, the IPv4 broadcast address, loopback, multicast and
/// link-local unicast. RFC1918 private addresses ARE global unicast in Go.
fn is_global_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_loopback()
                && !v4.is_multicast()
                && !v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                // fe80::/10 — `is_unicast_link_local` is still unstable
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Build the reply carrying an answer: its response code and one record per
/// address of the question's type (none makes it a NODATA / NXDOMAIN reply),
/// plus our EDNS0 OPT record when the client sent one.
/// The question type must match the original query.
/// mihomo compat: browsers send both A and AAAA queries; mismatched responses get discarded.
fn build_dns_response(query: &Query, answer: &Answer, udp_size_limit: Option<usize>) -> Vec<u8> {
    let mut ips: Vec<&IpAddr> = answer
        .ips
        .iter()
        .filter(|ip| ip.is_ipv4() == (query.qtype == TYPE_A))
        .collect();

    // Header and question section — must echo back the ORIGINAL query type
    let mut response = begin_dns_response(query, answer.rcode);

    // mihomo compat: dns/server.go ServeDNS → miekg/dns Msg.Truncate — "fit
    // the reply into the client's advertised buffer size, setting the TC bit
    // if records must be dropped; 512 when no OPT present".
    let size = match udp_size_limit {
        Some(limit) => {
            let advertised = query.edns0.map_or(512, |(size, _)| size as usize);
            limit.min(advertised).max(512)
        }
        // What the 2-byte length prefix of a stream transport can frame.
        None => u16::MAX as usize,
    };
    let opt_len = if query.edns0.is_some() { 11 } else { 0 };
    let record_len = if query.qtype == TYPE_A { 16 } else { 28 };
    let room = size.saturating_sub(response.len() + opt_len) / record_len;
    if ips.len() > room {
        ips.truncate(room);
        response[2] |= 0x02; // TC
    }

    // Answer section
    response[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes());
    for ip in ips {
        response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to question
        match ip {
            IpAddr::V4(ipv4) => {
                response.extend_from_slice(&[0x00, 0x01]); // Type A
                response.extend_from_slice(&[0x00, 0x01]); // Class IN
                response.extend_from_slice(&answer.ttl.to_be_bytes());
                response.extend_from_slice(&[0x00, 0x04]);
                response.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                response.extend_from_slice(&[0x00, 0x1c]); // Type AAAA
                response.extend_from_slice(&[0x00, 0x01]); // Class IN
                response.extend_from_slice(&answer.ttl.to_be_bytes());
                response.extend_from_slice(&[0x00, 0x10]);
                response.extend_from_slice(&ipv6.octets());
            }
        }
    }

    if let Some((_, dnssec_ok)) = query.edns0 {
        append_edns0(&mut response, dnssec_ok);
    }

    response
}

/// Start a reply: the header, with no records yet, and the echoed question.
fn begin_dns_response(query: &Query, rcode: u8) -> Vec<u8> {
    let mut response = Vec::with_capacity(128);
    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(&[0x81, 0x80 | rcode]); // Flags: response, recursion desired+available
    response.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    response.extend_from_slice(&[0x00; 6]); // Answers, authority, additional: 0
    append_dns_question(&mut response, &query.domain, query.qtype);
    response
}

/// Append the question section for `domain`/`qtype` (class IN).
fn append_dns_question(response: &mut Vec<u8>, domain: &str, qtype: u16) {
    for part in domain.split('.') {
        response.push(part.len() as u8);
        response.extend_from_slice(part.as_bytes());
    }
    response.push(0);
    response.extend_from_slice(&qtype.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x01]); // Class IN
}

/// Build a DNS SERVFAIL response.
/// mihomo compat: server.go — the reply echoes the question section (some
/// stub resolvers discard question-less replies and retry until timeout).
fn build_dns_servfail(query: &Query) -> Vec<u8> {
    begin_dns_response(query, 2)
}

#[cfg(test)]
mod tests {
    use super::upstream::test_support::{nameserver, reply, truncating_nameserver};
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Helper: create a minimal DnsResolver for testing (no FakeIP, no upstream).
    fn test_resolver() -> DnsResolver {
        DnsResolver {
            config: DnsConfig::default(),
            cache: DnsCache::new(100),
            fakeip: None,
            hosts: std::collections::HashMap::new(),
            fakeip_geosite_codes: Vec::new(),
            geosite_checker: None,
            fakeip_ruleset_names: Vec::new(),
            ruleset_checker: None,
            ip_to_host: parking_lot::Mutex::default(),
            proxy_dns_cache: DashMap::new(),
            proxy_dns_inflight: DashMap::new(),
        }
    }

    /// Helper: fake-ip resolver over the given range with an empty filter.
    fn fakeip_resolver_over(range: &str) -> DnsResolver {
        let mut r = test_resolver();
        r.fakeip = Some(FakeIpPool::new(range, &[], "blacklist").unwrap());
        r
    }

    /// Helper: fake-ip resolver over 198.18.0.0/16 with an empty filter.
    fn fakeip_test_resolver() -> DnsResolver {
        fakeip_resolver_over("198.18.0.0/16")
    }

    /// Helper: a client query, with an EDNS0 OPT record of the given
    /// (UDP payload size, DO bit) if any.
    fn client_query(domain: &str, qtype: u16, edns0: Option<(u16, bool)>) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0];
        query.push(edns0.is_some() as u8);
        append_dns_question(&mut query, domain, qtype);
        if let Some((size, dnssec_ok)) = edns0 {
            query.push(0);
            query.extend_from_slice(&TYPE_OPT.to_be_bytes());
            query.extend_from_slice(&size.to_be_bytes());
            query.extend_from_slice(&[0, 0, if dnssec_ok { 0x80 } else { 0 }, 0, 0, 0]);
        }
        query
    }

    /// Helper: the response code and the answer addresses of a reply built by
    /// `process_dns_query`.
    fn decode(reply: &[u8]) -> (u8, Vec<IpAddr>) {
        let mut pos = upstream::skip_dns_name(reply, 12).unwrap() + 4;
        let mut ips = Vec::new();
        for _ in 0..u16::from_be_bytes([reply[6], reply[7]]) {
            let rdlen = u16::from_be_bytes([reply[pos + 10], reply[pos + 11]]) as usize;
            let rdata = &reply[pos + 12..pos + 12 + rdlen];
            ips.push(match <[u8; 4]>::try_from(rdata) {
                Ok(v4) => IpAddr::from(v4),
                Err(_) => IpAddr::from(<[u8; 16]>::try_from(rdata).unwrap()),
            });
            pos += 12 + rdlen;
        }
        (reply[3] & 0x0f, ips)
    }

    /// Helper: a loopback address whose UDP and TCP port are both free.
    async fn free_addr() -> SocketAddr {
        loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap();
            if UdpSocket::bind(addr).await.is_ok() {
                return addr;
            }
        }
    }

    /// Helper: ask the listener at `server` over UDP for the A record of `domain`.
    async fn ask_udp(server: SocketAddr, domain: &str) -> IpAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = client_query(domain, TYPE_A, None);
        socket.send_to(&query, server).await.unwrap();
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .expect("the listener answers")
            .unwrap();
        decode(&buf[..n]).1[0]
    }

    /// Helper: ask the listener at `server` over TCP for the A record of `domain`.
    async fn ask_tcp(stream: &mut tokio::net::TcpStream, domain: &str) -> IpAddr {
        let query = client_query(domain, TYPE_A, None);
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&query).await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).await.unwrap();
        decode(&reply).1[0]
    }

    /// Regression: the listener kept answering from the resolver it was
    /// started with, so after a config reload new names got fake IPs from the
    /// OLD pool while connections looked them up in the NEW one — a miss, and
    /// the flow was dropped.
    ///
    /// mihomo compat: executor.go updateDNS → dns/server.go ReCreateServer —
    /// the same address keeps the sockets and swaps the service
    /// (`SetService`), a changed one re-binds, disabled DNS stops listening.
    #[tokio::test]
    async fn listener_answers_from_the_resolver_of_the_latest_reload() {
        let boot = Arc::new(fakeip_resolver_over("198.18.0.0/16"));
        let reloaded = Arc::new(fakeip_resolver_over("10.10.0.0/16"));
        let mut server = None;

        let addr = free_addr().await;
        recreate_listener(&mut server, &addr.to_string(), Some(boot.clone())).await;
        assert!(boot.is_fake_ip(&ask_udp(addr, "before.example.com").await));
        // A TCP connection opened before the reload...
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(boot.is_fake_ip(&ask_tcp(&mut tcp, "before.example.com").await));

        // Reload with an unchanged `dns.listen`: same sockets, new resolver.
        recreate_listener(&mut server, &addr.to_string(), Some(reloaded.clone())).await;
        let ip = ask_udp(addr, "after.example.com").await;
        assert!(reloaded.is_fake_ip(&ip), "{ip} is not from the new pool");
        assert_eq!(
            reloaded.reverse_lookup(&ip).as_deref(),
            Some("after.example.com")
        );
        // ...is answered from the new resolver as well.
        assert!(reloaded.is_fake_ip(&ask_tcp(&mut tcp, "after-tcp.example.com").await));

        // Reload with a changed `dns.listen`: the old port is released, the
        // new one answers.
        let moved = free_addr().await;
        recreate_listener(&mut server, &moved.to_string(), Some(reloaded.clone())).await;
        assert!(reloaded.is_fake_ip(&ask_udp(moved, "moved.example.com").await));
        drop(UdpSocket::bind(addr).await.expect("old UDP port released"));
        drop(
            TcpListener::bind(addr)
                .await
                .expect("old TCP port released"),
        );

        // A host-less address listens on every address of the system.
        recreate_listener(
            &mut server,
            &format!(":{}", addr.port()),
            Some(reloaded.clone()),
        )
        .await;
        assert!(reloaded.is_fake_ip(&ask_udp(addr, "hostless.example.com").await));

        // DNS disabled: the listener stops.
        recreate_listener(&mut server, "", None).await;
        assert!(server.is_none());
        drop(UdpSocket::bind(addr).await.expect("UDP port released"));
    }

    /// mihomo compat: dns/server.go ReCreateServer / Go's net.Listen — a
    /// host-less `dns.listen` (":1053") means every address, dual-stack first;
    /// port 0 means no listener; anything else must be `ip:port`.
    #[test]
    fn listen_addresses() {
        let addrs = |addr| {
            listen_addrs(addr)
                .unwrap()
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(addrs(":1053"), ["[::]:1053", "0.0.0.0:1053"]);
        assert_eq!(addrs("0.0.0.0:7874"), ["0.0.0.0:7874"]);
        assert_eq!(addrs("[::1]:53"), ["[::1]:53"]);
        assert!(addrs("127.0.0.1:0").is_empty());
        assert!(addrs(":0").is_empty());
        assert!(listen_addrs("1053").is_err());
        assert!(listen_addrs(":dns").is_err());
    }

    /// Regression: `resolve_real_ip` caches real IPs under the plain domain key
    /// for rule matching. `serve_ip()` (the DNS-server path) must still answer
    /// with a fake IP — mihomo composes withFakeIP ahead of the resolver cache,
    /// so a real IP can never be served for a non-bypassed domain. Serving one
    /// makes the client cache a CDN address for the full TTL and pins later
    /// connections to a stale edge (wrong certificate).
    #[tokio::test]
    async fn fakeip_answer_is_not_shadowed_by_real_ip_cache() {
        let r = fakeip_test_resolver();
        let first = r.serve_ip("cdn.example.com", TYPE_A).await.unwrap().ips;
        assert!(r.is_fake_ip(&first[0]));

        // What resolve_real_ip() does after an on-demand GEOIP/IP-CIDR lookup.
        let real = IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1));
        r.cache.insert(
            "cdn.example.com".to_string(),
            &Answer {
                rcode: 0,
                ips: vec![real],
                ttl: 300,
            },
        );

        let second = r.serve_ip("cdn.example.com", TYPE_A).await.unwrap().ips;
        assert_eq!(second, first, "serve_ip() returned the real IP {second:?}");
    }

    /// mihomo compat: fake-ip answers advertise TTL 1 so a client re-queries
    /// instead of pinning a mapping the pool may have recycled.
    #[tokio::test]
    async fn fakeip_answer_advertises_ttl_one() {
        let r = fakeip_test_resolver();
        let answer = r.serve_ip("cdn.example.com", TYPE_A).await.unwrap();
        assert!(r.is_fake_ip(&answer.ips[0]));
        assert_eq!(answer.ttl, FAKEIP_TTL);
    }

    /// Regression: a real answer served from cache advertises the REMAINING TTL,
    /// not a fixed 600 — otherwise a client holds a CDN address long past the
    /// point the edge stops serving the name.
    #[tokio::test]
    async fn cached_real_answer_advertises_remaining_ttl() {
        let r = test_resolver(); // redir-host mode (no fake-ip pool)
        let real = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        r.cache.insert(
            "direct.example.com".to_string(),
            &Answer {
                rcode: 0,
                ips: vec![real],
                ttl: 30,
            },
        );

        let answer = r.serve_ip("direct.example.com", TYPE_A).await.unwrap();
        assert_eq!(answer.ips, [real]);
        assert!(
            (1..=30).contains(&answer.ttl),
            "expected a counted-down TTL, got {}",
            answer.ttl
        );
    }

    /// Regression: an NXDOMAIN or empty upstream answer reached the client as
    /// SERVFAIL.
    ///
    /// mihomo compat: dns/middleware.go withResolver relays whatever reply won
    /// the race with its response code (`msg.SetRcode(r, msg.Rcode)`), and
    /// dns/util.go putMsgToCache caches it for the TTL of its SOA.
    #[tokio::test]
    async fn negative_upstream_answers_reach_the_client_and_the_cache() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let server = nameserver(move |q| {
            counter.fetch_add(1, Ordering::SeqCst);
            // NXDOMAIN for "missing.…", an empty answer for anything else.
            let rcode = if q[13] == b'm' { 3 } else { 0 };
            reply(q, rcode, &[], &[(6, 600, vec![0; 22])])
        })
        .await;
        let mut r = test_resolver();
        r.config.nameserver = vec![server];

        let missing = client_query("missing.example.com", TYPE_A, None);
        let nxdomain = process_dns_query(&missing, &r, None).await.unwrap();
        assert_eq!(decode(&nxdomain), (3, vec![]));

        let empty = client_query("empty.example.com", TYPE_A, None);
        let nodata = process_dns_query(&empty, &r, None).await.unwrap();
        assert_eq!(decode(&nodata), (0, vec![]));

        // Asked again, the negative answer comes from the cache.
        let nxdomain = process_dns_query(&missing, &r, None).await.unwrap();
        assert_eq!(decode(&nxdomain), (3, vec![]));
        assert_eq!(asked.load(Ordering::SeqCst), 2);

        // An internal lookup of such a name fails with mihomo's ErrIPNotFound.
        let err = r.resolve_real_ip("missing.example.com").await.unwrap_err();
        assert_eq!(err.to_string(), "couldn't find ip: missing.example.com");
    }

    /// Every address of the upstream answer reaches the client and is
    /// recorded for reverse lookup — also when the answer comes from the
    /// cache: mihomo's withMapping wraps the resolver, its cache included.
    #[tokio::test]
    async fn real_answers_carry_every_address_and_map_it_on_cache_hits_too() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let server = nameserver(move |q| {
            counter.fetch_add(1, Ordering::SeqCst);
            let answers = [
                (TYPE_A, 60, vec![203, 0, 113, 1]),
                (TYPE_A, 60, vec![203, 0, 113, 2]),
            ];
            reply(q, 0, &answers, &[])
        })
        .await;
        let mut r = test_resolver();
        r.config.nameserver = vec![server];
        let ips: Vec<IpAddr> = vec![
            "203.0.113.1".parse().unwrap(),
            "203.0.113.2".parse().unwrap(),
        ];
        let query = client_query("cdn.example.com", TYPE_A, None);

        let fresh = process_dns_query(&query, &r, None).await.unwrap();
        assert_eq!(decode(&fresh), (0, ips.clone()));

        r.flush_mapping();
        let cached = process_dns_query(&query, &r, None).await.unwrap();
        assert_eq!(decode(&cached), (0, ips.clone()));
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        for ip in &ips {
            assert_eq!(r.reverse_lookup(ip).as_deref(), Some("cdn.example.com"));
        }
    }

    /// mihomo compat: dns/server.go ServeDNS → miekg/dns Msg.Truncate — a UDP
    /// reply fits the size the client advertises (512 without EDNS0): records
    /// beyond it are dropped and TC tells the client to retry over TCP. The
    /// TUN hijack never sends more than 2048 bytes (resolver.RelayDnsPacket).
    #[tokio::test]
    async fn udp_reply_is_truncated_to_what_the_client_takes() {
        let r = test_resolver();
        r.cache.insert(
            "many.example.com".to_string(),
            &Answer {
                rcode: 0,
                ips: (0..130)
                    .map(|i| Ipv4Addr::new(203, 0, 113, i).into())
                    .collect(),
                ttl: 60,
            },
        );
        // (records, TC bit, length) of the reply to a client advertising
        // `edns0`, sent over a transport with the given size limit.
        let ask = |edns0, limit| {
            let r = &r;
            async move {
                let query = client_query("many.example.com", TYPE_A, edns0);
                let reply = process_dns_query(&query, r, limit).await.unwrap();
                (decode(&reply).1.len(), reply[2] & 0x02 != 0, reply.len())
            }
        };

        // 12 header + 22 question bytes, then 16 per record (+ 11 for OPT).
        assert_eq!(ask(None, None).await, (130, false, 34 + 130 * 16));
        assert_eq!(ask(None, Some(usize::MAX)).await, (29, true, 34 + 29 * 16));
        let edns0 = Some((4096, false));
        assert_eq!(
            ask(edns0, Some(usize::MAX)).await,
            (130, false, 34 + 130 * 16 + 11)
        );
        assert_eq!(
            ask(edns0, Some(SAFE_DNS_PACKET_SIZE)).await,
            (125, true, 34 + 125 * 16 + 11)
        );
    }

    /// mihomo compat: dns/client.go — the query of a truncated UDP reply is
    /// sent again over TCP. A relayed query type gets that for a client on
    /// TCP; a client on UDP is handed the truncated reply and comes back over
    /// TCP by itself.
    #[tokio::test]
    async fn relayed_truncated_reply_is_retried_over_tcp_for_tcp_clients() {
        let server =
            truncating_nameserver(|q| reply(q, 0, &[(16, 60, vec![2, b'h', b'i'])], &[])).await;
        let mut r = test_resolver();
        r.config.nameserver = vec![server];
        let query = client_query("txt.example.com", 16, None);

        let tcp = process_dns_query(&query, &r, None).await.unwrap();
        assert_eq!((tcp[2] & 0x02, &tcp[6..8]), (0, &[0, 1][..]));

        let udp = process_dns_query(&query, &r, Some(usize::MAX))
            .await
            .unwrap();
        assert_eq!((udp[2] & 0x02, &udp[6..8]), (0x02, &[0, 0][..]));
    }

    /// mihomo compat: dns/service.go ServeMsg — a client that asked with an
    /// EDNS0 OPT record gets our own OPT back (payload size 1232, its DO bit
    /// echoed) unless the reply carries one already; a client that did not,
    /// gets none. The SERVFAIL of dns/server.go ServeDNS is built bare.
    #[tokio::test]
    async fn edns0_opt_is_echoed_to_clients_that_sent_one() {
        let r = fakeip_test_resolver();
        let name = "www.example.com";

        let plain = process_dns_query(&client_query(name, TYPE_A, None), &r, None)
            .await
            .unwrap();
        assert_eq!((edns0(&plain), &plain[10..12]), (None, &[0, 0][..]));

        for dnssec_ok in [true, false] {
            let query = client_query(name, TYPE_A, Some((4096, dnssec_ok)));
            let reply = process_dns_query(&query, &r, None).await.unwrap();
            assert_eq!(edns0(&reply), Some((1232, dnssec_ok)));
            assert_eq!(&reply[10..12], [0, 1]);
            assert!(r.is_fake_ip(&decode(&reply).1[0]));
        }

        // An empty answer carries it too.
        let query = client_query(name, TYPE_HTTPS, Some((4096, false)));
        let https = process_dns_query(&query, &r, None).await.unwrap();
        assert_eq!(edns0(&https), Some((1232, false)));

        // A relayed reply (other query types) gets it unless the upstream's
        // reply has an OPT record of its own.
        let server = nameserver(|q| {
            let mut answer = reply(q, 0, &[(16, 60, vec![2, b'h', b'i'])], &[]);
            if q[13] == b'o' {
                answer[11] = 1;
                answer.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
            }
            answer
        })
        .await;
        let mut relay = test_resolver();
        relay.config.nameserver = vec![server];
        let query = client_query("txt.example.com", 16, Some((4096, false)));
        let relayed = process_dns_query(&query, &relay, None).await.unwrap();
        assert_eq!(
            (edns0(&relayed), &relayed[10..12]),
            (Some((1232, false)), &[0, 1][..])
        );
        let query = client_query("opt.example.com", 16, Some((4096, false)));
        let relayed = process_dns_query(&query, &relay, None).await.unwrap();
        assert_eq!(
            (edns0(&relayed), &relayed[10..12]),
            (Some((4096, false)), &[0, 1][..])
        );

        // No nameserver that can answer: SERVFAIL, without OPT.
        let mut failing = test_resolver();
        failing.config.nameserver = vec!["dhcp://eth0".to_string()];
        let query = client_query(name, TYPE_A, Some((4096, true)));
        let servfail = process_dns_query(&query, &failing, None).await.unwrap();
        assert_eq!((servfail[3] & 0x0f, edns0(&servfail)), (2, None));
    }

    /// Regression: the controller's `/dns/query` went through the fake-ip
    /// path and handed out — allocated — a fake IP, whatever type was asked.
    ///
    /// mihomo compat: hub/route/dns.go queryDNS exchanges the question with
    /// `resolver.DefaultResolver`: the real answer, of the requested type.
    #[tokio::test]
    async fn controller_query_asks_the_resolver_not_the_fake_ip_pool() {
        let server = nameserver(|q| {
            let txt = (16, 60, vec![2, b'h', b'i']);
            let a = (TYPE_A, 60, vec![203, 0, 113, 7]);
            let asked_txt = q[q.len() - 3] == 16;
            reply(q, 0, &[if asked_txt { txt } else { a }], &[])
        })
        .await;
        let mut r = fakeip_test_resolver();
        r.config.nameserver = vec![server];

        let a = r.query("www.example.com", TYPE_A).await.unwrap();
        assert_eq!(decode(&a), (0, vec!["203.0.113.7".parse().unwrap()]));
        // The pool is untouched: its first address is still to be handed out.
        let first = r.serve_ip("first.example.com", TYPE_A).await.unwrap();
        assert_eq!(first.ips, [IpAddr::V4(Ipv4Addr::new(198, 18, 0, 4))]);

        let txt = r.query("www.example.com", 16).await.unwrap();
        let record = upstream::skip_dns_name(&txt, 12).unwrap() + 4;
        assert_eq!(
            (&txt[6..8], &txt[record + 2..record + 4]),
            (&[0, 1][..], &[0, 16][..])
        );
    }

    /// mihomo compat: dns/middleware.go withFakeIP — for a name the filter
    /// does not skip, SVCB (64) and HTTPS (65) get an empty answer, and so
    /// does AAAA while there is no IPv6 fake-ip pool, `ipv6: true` or not.
    #[tokio::test]
    async fn fake_ip_answers_svcb_https_and_aaaa_empty() {
        let mut r = fakeip_test_resolver();
        r.config.ipv6 = true;
        // Whatever reached the resolver would come back as SERVFAIL.
        r.config.nameserver = vec!["dhcp://eth0".to_string()];

        for qtype in [TYPE_SVCB, TYPE_HTTPS, TYPE_AAAA] {
            let query = client_query("www.example.com", qtype, None);
            let reply = process_dns_query(&query, &r, None).await.unwrap();
            assert_eq!(decode(&reply), (0, vec![]), "qtype {qtype}");
        }
    }

    /// mihomo compat: config.go parseDomain — the `geosite:` / `rule-set:`
    /// prefixes of fake-ip-filter entries are case-insensitive and name
    /// comma-separated lists.
    #[tokio::test]
    async fn fake_ip_filter_geosite_and_rule_set_entries() {
        let config = DnsConfig {
            enable: true,
            fake_ip_filter: vec![
                "GEOSITE:cn,private".to_string(),
                "Rule-Set:lan,direct".to_string(),
                "+.lan".to_string(),
            ],
            ..Default::default()
        };
        let mut r = DnsResolver::new(&config).await.unwrap();
        assert_eq!(r.fakeip_geosite_codes, ["cn", "private"]);
        assert_eq!(r.fakeip_ruleset_names(), ["lan", "direct"]);

        r.set_geosite_checker(|domain, code| code == "private" && domain == "printer.corp");
        r.set_ruleset_checker(|domain, name| name == "direct" && domain == "bank.example");
        assert!(r.should_bypass_fakeip("printer.corp"));
        assert!(r.should_bypass_fakeip("bank.example"));
        assert!(r.should_bypass_fakeip("router.lan"));
        assert!(!r.should_bypass_fakeip("www.example.com"));
    }

    /// Regression: proxy server hostnames were resolved through
    /// `default-nameserver` (114.114.114.114 / 8.8.8.8 unless configured)
    /// and never through `nameserver`, and an answer inside `fake-ip-range`
    /// was rejected.
    ///
    /// mihomo compat: hub/executor/executor.go updateDNS — without
    /// `proxy-server-nameserver` the resolver of proxy server hosts is the
    /// main one; `default-nameserver` only bootstraps nameserver hostnames.
    /// Its answers are used as they are, and hosts come first
    /// (component/resolver/resolver.go LookupIPWithResolver).
    #[tokio::test]
    async fn proxy_server_resolves_through_nameserver() {
        let main = nameserver(|q| reply(q, 0, &[(TYPE_A, 60, vec![198, 18, 5, 5])], &[])).await;
        let bootstrap = nameserver(|q| reply(q, 0, &[(TYPE_A, 60, vec![192, 0, 2, 1])], &[])).await;
        let mut r = fakeip_test_resolver();
        r.config.nameserver = vec![main];
        r.config.default_nameserver = vec![bootstrap];
        let pinned = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        r.hosts.insert("pinned.example.com".to_string(), pinned);

        let ip = r.resolve_proxy_server("node.example.com").await.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 18, 5, 5)));
        assert!(r.is_fake_ip(&ip), "the answer is inside fake-ip-range");
        assert_eq!(
            r.resolve_proxy_server("pinned.example.com").await.unwrap(),
            pinned
        );
    }

    /// mihomo compat: dns/resolver.go NewResolver — the resolver built for
    /// `proxy-server-nameserver` knows those servers and
    /// `proxy-server-nameserver-policy`, nothing else: when they fail, the
    /// lookup fails instead of falling through to other nameservers.
    #[tokio::test]
    async fn proxy_server_nameserver_is_exclusive_when_configured() {
        let other = nameserver(|q| reply(q, 0, &[(TYPE_A, 60, vec![192, 0, 2, 1])], &[])).await;
        let proxy = nameserver(|q| reply(q, 0, &[(TYPE_A, 60, vec![198, 18, 5, 5])], &[])).await;
        let policy = nameserver(|q| reply(q, 0, &[(TYPE_A, 60, vec![203, 0, 113, 7])], &[])).await;
        let failing = nameserver(|q| reply(q, 2, &[], &[])).await;
        let mut r = fakeip_test_resolver();
        r.config.nameserver = vec![other.clone()];
        r.config.default_nameserver = vec![other];
        r.config.proxy_server_nameserver = vec![proxy];
        r.config.proxy_server_nameserver_policy =
            serde_yaml::from_str(&format!("'+.policy.example': '{policy}'")).unwrap();

        assert_eq!(
            r.resolve_proxy_server("node.example.com").await.unwrap(),
            IpAddr::V4(Ipv4Addr::new(198, 18, 5, 5))
        );
        assert_eq!(
            r.resolve_proxy_server("node.policy.example").await.unwrap(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );

        r.config.proxy_server_nameserver = vec![failing];
        let err = r
            .resolve_proxy_server("other.example.com")
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "all DNS requests failed, first error: server failure: SERVFAIL"
        );
    }

    /// Regression: the rule-matching resolution path must not claim the reverse
    /// mapping. mihomo's enhancer mapping is written only by the DNS server
    /// middleware; recording internal resolutions makes a shared CDN address
    /// reverse-map to an unrelated domain, and preHandleMetadata then rewrites
    /// the connection's host to it.
    #[tokio::test]
    async fn resolve_real_ip_does_not_record_reverse_mapping() {
        let r = fakeip_test_resolver();
        // An IP literal short-circuits before any upstream query.
        let ip = r.resolve_real_ip("104.16.1.1").await.unwrap();
        assert_eq!(r.reverse_lookup(&ip), None);
    }

    #[test]
    fn record_ip_mapping_skips_non_global_unicast() {
        let r = test_resolver();
        for addr in ["0.0.0.0", "127.0.0.1", "255.255.255.255", "224.0.0.1"] {
            let ip: IpAddr = addr.parse().unwrap();
            r.record_ip_mapping(ip, "blocked.example.com");
            assert_eq!(r.reverse_lookup(&ip), None, "{addr} should not be mapped");
        }
        // A private address is global unicast in Go and must still be recorded.
        let lan: IpAddr = "192.168.1.10".parse().unwrap();
        r.record_ip_mapping(lan, "nas.lan");
        assert_eq!(r.reverse_lookup(&lan), Some("nas.lan".to_string()));
    }

    #[test]
    fn record_and_reverse_lookup_ip_mapping() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // No mapping yet
        assert_eq!(resolver.reverse_lookup(&ip), None);

        // Record a mapping
        resolver.record_ip_mapping(ip, "example.com");

        // Now reverse lookup should succeed
        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn insert_host_by_ip_public_api() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        resolver.insert_host_by_ip(ip, "dns.google");
        assert_eq!(resolver.reverse_lookup(&ip), Some("dns.google".to_string()));
    }

    #[test]
    fn mapping_overwrites_previous_entry() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        resolver.record_ip_mapping(ip, "first.example.com");
        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("first.example.com".to_string())
        );

        // Overwrite with new domain (same IP, different CNAME target)
        resolver.record_ip_mapping(ip, "second.example.com");
        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("second.example.com".to_string())
        );
    }

    /// mihomo compat: dns/enhancer.go NewEnhancer — the mapping is
    /// `lru.New(lru.WithSize(4096))`: entries have no age limit
    /// (common/lru/lrucache.go get() expires only when maxAge is set) and the
    /// least recently used one is evicted beyond 4096.
    ///
    /// Replaces `expired_mapping_returns_none_and_is_removed` and
    /// `zero_ttl_gets_minimum_one_second`, which pinned an expiry by record
    /// TTL that mihomo's mapping does not have.
    #[test]
    fn mapping_is_an_lru_of_4096_entries_without_expiry() {
        let resolver = test_resolver();
        let ip = |n: u32| IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + n));
        let host = |n: u32| Some(format!("host{n}.example.com"));
        for n in 0..HOST_MAPPING_SIZE as u32 {
            resolver.record_ip_mapping(ip(n), &host(n).unwrap());
        }

        // A lookup makes the oldest entry the most recently used one...
        assert_eq!(resolver.reverse_lookup(&ip(0)), host(0));
        // ...so the next new entry pushes out the second oldest instead.
        resolver.record_ip_mapping(ip(HOST_MAPPING_SIZE as u32), "new.example.com");
        assert_eq!(resolver.reverse_lookup(&ip(1)), None);
        assert_eq!(resolver.reverse_lookup(&ip(0)), host(0));
        assert_eq!(resolver.reverse_lookup(&ip(2)), host(2));
        assert_eq!(resolver.ip_to_host.lock().entries.len(), HOST_MAPPING_SIZE);
    }

    #[test]
    fn flush_mapping_clears_all_entries() {
        let resolver = test_resolver();

        resolver.record_ip_mapping(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "one.example.com");
        resolver.record_ip_mapping(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), "two.example.com");

        assert_eq!(resolver.ip_to_host.lock().entries.len(), 2);

        resolver.flush_mapping();

        assert_eq!(resolver.ip_to_host.lock().entries.len(), 0);
        assert_eq!(
            resolver.reverse_lookup(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            None
        );
    }

    #[test]
    fn flush_cache_also_flushes_mapping() {
        let resolver = test_resolver();

        resolver.record_ip_mapping(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)), "three.example.com");
        assert_eq!(resolver.ip_to_host.lock().entries.len(), 1);

        resolver.flush_cache();

        assert_eq!(resolver.ip_to_host.lock().entries.len(), 0);
    }

    #[test]
    fn multiple_ips_for_different_domains() {
        let resolver = test_resolver();

        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46));

        resolver.record_ip_mapping(ip1, "example.com");
        resolver.record_ip_mapping(ip2, "google.com");

        assert_eq!(
            resolver.reverse_lookup(&ip1),
            Some("example.com".to_string())
        );
        assert_eq!(
            resolver.reverse_lookup(&ip2),
            Some("google.com".to_string())
        );
    }

    #[test]
    fn ipv6_mapping_works() {
        let resolver = test_resolver();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        resolver.record_ip_mapping(ip, "ipv6.example.com");

        assert_eq!(
            resolver.reverse_lookup(&ip),
            Some("ipv6.example.com".to_string())
        );
    }

    #[test]
    fn reverse_lookup_no_fakeip_no_mapping_returns_none() {
        let resolver = test_resolver();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        // No FakeIP pool, no mapping recorded
        assert_eq!(resolver.reverse_lookup(&ip), None);
    }
}
