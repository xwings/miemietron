pub mod geodata;
pub mod geoip;
pub mod geosite;
pub mod mrs;
pub mod process;
pub mod provider;

use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Per-rule statistics tracked atomically.
/// mihomo compat: matches the `extra` field in GET /rules responses.
pub struct RuleStats {
    pub hit_count: AtomicU64,
    pub disabled: AtomicBool,
}

use crate::config::rules::{RuleProviderConfig, RuleString};

/// The action a rule resolves to.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Proxy(String), // Proxy group name
    Direct,
    Reject,
    RejectDrop,
}

/// Metadata about a connection used for rule matching.
#[derive(Debug, Clone, Default)]
pub struct RuleMetadata {
    pub domain: Option<String>,
    pub dst_ip: Option<IpAddr>,
    pub src_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub src_port: u16,
    pub network: &'static str, // "tcp" or "udp" — avoids heap allocation
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub in_port: Option<u16>,
    pub in_type: Option<&'static str>, // "http-proxy", "socks5", etc.
    pub in_user: Option<String>,
    pub in_name: Option<String>,
    pub uid: Option<u32>,
    pub dscp: Option<u8>,
}

/// Matcher discriminant, derived once from `rule_type` at parse time.
///
/// `rule_type: String` stays authoritative for display (`GET /rules`,
/// `rule_type_display`, `rule_record_size`) and for the unknown-type warning;
/// this is purely the dispatch key, so the per-connection walk over ~7k rules
/// compares one discriminant instead of running a 36-arm string match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RuleKind {
    /// A type mihomo's `rules/parser.go` doesn't know. Never matches — this is
    /// the old `_ => None` arm of `match_single_rule`.
    #[default]
    Unknown,
    Match,
    Network,
    Domain,
    DomainSuffix,
    DomainSuffixStrict,
    DomainStar,
    DomainKeyword,
    DomainWildcard,
    DomainRegex,
    GeoSite,
    GeoIp,
    SrcGeoIp,
    /// `IP-CIDR` and `IP-CIDR6` — mihomo parses both through NewIPCIDR.
    IpCidr,
    SrcIpCidr,
    IpSuffix,
    SrcIpSuffix,
    IpAsn,
    SrcIpAsn,
    DstPort,
    SrcPort,
    InPort,
    InType,
    InUser,
    InName,
    Uid,
    Dscp,
    ProcessName,
    ProcessPath,
    ProcessNameRegex,
    ProcessPathRegex,
    ProcessNameWildcard,
    ProcessPathWildcard,
    And,
    Or,
    Not,
    SubRule,
}

/// Per-rule pre-parsed payload, built at parse time so the matcher never
/// touches the payload *string*.
///
/// Replaces six `HashMap<usize, _>` side tables keyed by the rule's index in
/// the engine's list. Living on the rule instead of beside it removes a hash +
/// probe per IP/port/regex rule per connection, and — more importantly — makes
/// the prepared state reachable from nested logic rules, which used to recurse
/// with `rule_idx = usize::MAX` and re-parse their CIDR/port payload on every
/// single match.
#[derive(Debug, Clone, Default)]
enum Prepared {
    /// No pre-parsing applies, or the payload failed to parse. In the latter
    /// case the matcher falls back to the string path, which fails the same way
    /// (a `Regex::new` that failed at load fails again → no match).
    #[default]
    None,
    Cidr(PreParsedCidr),
    Suffix(PreParsedSuffix),
    Ports(Vec<(u16, u16)>),
    Asn(u32),
    /// UID / DSCP range list (mihomo IntRanges).
    Ranges(Vec<(u32, u32)>),
    Regex(Regex),
}

/// Parsed rule entry.
#[derive(Debug, Clone, Default)]
pub struct ParsedRule {
    pub rule_type: String,
    pub payload: String,
    pub target: String,
    pub params: Vec<String>,
    /// Parsed sub-rules for logic types. AND/OR: the condition list; NOT: one
    /// condition; SUB-RULE: the one gating condition (the group name is in
    /// `target`, mihomo logic.go NewSubRule). Empty for plain rules.
    pub sub_rules: Vec<ParsedRule>,
    /// Dispatch key derived from `rule_type` — see [`RuleKind`].
    kind: RuleKind,
    /// Pre-parsed payload — see [`Prepared`].
    prepared: Prepared,
    /// `src` param: match against the source IP instead of the destination.
    is_src: bool,
    /// `no-resolve` param, or `src` (which implies it).
    no_resolve: bool,
}

impl ParsedRule {
    /// Derive `kind`, `prepared`, `is_src` and `no_resolve` from the
    /// already-populated `rule_type` / `payload` / `params`.
    ///
    /// Must run on every rule that can reach the matcher, and must re-run after
    /// any mutation of those three fields — RULE-SET expansion appends the
    /// reference's params to each expanded rule, which changes `is_src`.
    fn finalized(mut self) -> Self {
        self.kind = rule_kind(&self.rule_type);
        (self.is_src, self.no_resolve) = parse_params(&self.params);
        self.prepared = match self.kind {
            RuleKind::IpCidr | RuleKind::SrcIpCidr => {
                PreParsedCidr::parse(&self.payload).map_or(Prepared::None, Prepared::Cidr)
            }
            RuleKind::IpSuffix | RuleKind::SrcIpSuffix => {
                PreParsedSuffix::parse(&self.payload).map_or(Prepared::None, Prepared::Suffix)
            }
            RuleKind::DstPort | RuleKind::SrcPort | RuleKind::InPort => {
                match parse_port_ranges(&self.payload) {
                    Ok(r) if !r.is_empty() => Prepared::Ports(r),
                    _ => Prepared::None,
                }
            }
            RuleKind::IpAsn | RuleKind::SrcIpAsn => {
                self.payload.parse().map_or(Prepared::None, Prepared::Asn)
            }
            RuleKind::Uid | RuleKind::Dscp => {
                parse_u32_ranges(&self.payload).map_or(Prepared::None, Prepared::Ranges)
            }
            // mihomo compat: domain_regex.go and process.go both use regexp2
            // with the IgnoreCase flag. Rust regex equivalent: (?i) prefix.
            RuleKind::DomainRegex | RuleKind::ProcessNameRegex | RuleKind::ProcessPathRegex => {
                let pattern = if self.payload.starts_with("(?i)") {
                    self.payload.clone()
                } else {
                    format!("(?i){}", &self.payload)
                };
                Regex::new(&pattern).map_or(Prepared::None, Prepared::Regex)
            }
            _ => Prepared::None,
        };
        self
    }
}

/// `rule_type` (already upper-cased by the parser) → [`RuleKind`].
/// mihomo compat: the case labels of `rules/parser.go` ParseRule.
fn rule_kind(rule_type: &str) -> RuleKind {
    match rule_type {
        "MATCH" => RuleKind::Match,
        "NETWORK" => RuleKind::Network,
        "DOMAIN" => RuleKind::Domain,
        "DOMAIN-SUFFIX" => RuleKind::DomainSuffix,
        "DOMAIN-SUFFIX-STRICT" => RuleKind::DomainSuffixStrict,
        "DOMAIN-STAR" => RuleKind::DomainStar,
        "DOMAIN-KEYWORD" => RuleKind::DomainKeyword,
        "DOMAIN-WILDCARD" => RuleKind::DomainWildcard,
        "DOMAIN-REGEX" => RuleKind::DomainRegex,
        "GEOSITE" => RuleKind::GeoSite,
        "GEOIP" => RuleKind::GeoIp,
        "SRC-GEOIP" => RuleKind::SrcGeoIp,
        "IP-CIDR" | "IP-CIDR6" => RuleKind::IpCidr,
        "SRC-IP-CIDR" => RuleKind::SrcIpCidr,
        "IP-SUFFIX" => RuleKind::IpSuffix,
        "SRC-IP-SUFFIX" => RuleKind::SrcIpSuffix,
        "IP-ASN" => RuleKind::IpAsn,
        "SRC-IP-ASN" => RuleKind::SrcIpAsn,
        "DST-PORT" => RuleKind::DstPort,
        "SRC-PORT" => RuleKind::SrcPort,
        "IN-PORT" => RuleKind::InPort,
        "IN-TYPE" => RuleKind::InType,
        "IN-USER" => RuleKind::InUser,
        "IN-NAME" => RuleKind::InName,
        "UID" => RuleKind::Uid,
        "DSCP" => RuleKind::Dscp,
        "PROCESS-NAME" => RuleKind::ProcessName,
        "PROCESS-PATH" => RuleKind::ProcessPath,
        "PROCESS-NAME-REGEX" => RuleKind::ProcessNameRegex,
        "PROCESS-PATH-REGEX" => RuleKind::ProcessPathRegex,
        "PROCESS-NAME-WILDCARD" => RuleKind::ProcessNameWildcard,
        "PROCESS-PATH-WILDCARD" => RuleKind::ProcessPathWildcard,
        "AND" => RuleKind::And,
        "OR" => RuleKind::Or,
        "NOT" => RuleKind::Not,
        "SUB-RULE" => RuleKind::SubRule,
        _ => RuleKind::Unknown,
    }
}

/// mihomo compat: `rules/common/base.go` ParseParams — `src` flips matching to
/// the source IP and implies no-resolve.
fn parse_params(params: &[String]) -> (bool, bool) {
    let is_src = params.iter().any(|p| p == "src");
    let no_resolve = is_src || params.iter().any(|p| p == "no-resolve");
    (is_src, no_resolve)
}

/// Pre-parsed CIDR for O(1) bitwise matching (avoids string parsing per match).
#[derive(Debug, Clone)]
enum PreParsedCidr {
    V4 { masked_net: u32, mask: u32 },
    V6 { masked_net: u128, mask: u128 },
}

impl PreParsedCidr {
    /// Parse a CIDR string into pre-computed mask + masked network.
    fn parse(cidr: &str) -> Option<Self> {
        let (addr_str, prefix_str) = cidr.split_once('/')?;
        let prefix_len: u8 = prefix_str.parse().ok()?;
        if let Ok(v4) = addr_str.parse::<std::net::Ipv4Addr>() {
            let mask = if prefix_len == 0 {
                0
            } else if prefix_len >= 32 {
                !0u32
            } else {
                !((1u32 << (32 - prefix_len)) - 1)
            };
            Some(PreParsedCidr::V4 {
                masked_net: u32::from(v4) & mask,
                mask,
            })
        } else if let Ok(v6) = addr_str.parse::<std::net::Ipv6Addr>() {
            let mask = if prefix_len == 0 {
                0
            } else if prefix_len >= 128 {
                !0u128
            } else {
                !((1u128 << (128 - prefix_len)) - 1)
            };
            Some(PreParsedCidr::V6 {
                masked_net: u128::from(v6) & mask,
                mask,
            })
        } else {
            None
        }
    }

    #[inline]
    fn matches(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (PreParsedCidr::V4 { masked_net, mask }, IpAddr::V4(v4)) => {
                (u32::from(*v4) & mask) == *masked_net
            }
            (PreParsedCidr::V6 { masked_net, mask }, IpAddr::V6(v6)) => {
                (u128::from(*v6) & mask) == *masked_net
            }
            _ => false,
        }
    }
}

/// Pre-parsed IP-SUFFIX payload: address bytes + trailing bit count.
/// mihomo compat: ipsuffix.go NewIPSuffix — netip.ParsePrefix rejects anything
/// else at config load.
#[derive(Debug, Clone)]
enum PreParsedSuffix {
    V4([u8; 4], u32),
    V6([u8; 16], u32),
}

impl PreParsedSuffix {
    /// Parse an IP-SUFFIX payload "addr/bits".
    fn parse(payload: &str) -> Option<Self> {
        let (addr_str, bits_str) = payload.split_once('/')?;
        let addr: IpAddr = addr_str.trim().parse().ok()?;
        let bits: u32 = bits_str.trim().parse().ok()?;
        match addr {
            IpAddr::V4(v4) => (bits <= 32).then(|| PreParsedSuffix::V4(v4.octets(), bits)),
            IpAddr::V6(v6) => (bits <= 128).then(|| PreParsedSuffix::V6(v6.octets(), bits)),
        }
    }

    /// mihomo compat: ipsuffix.go Match — compares the TRAILING `bits` bits of
    /// the address against the payload address ("IP-SUFFIX,8.8.8.8/24" matches
    /// any x.8.8.8). Family mismatch never matches.
    #[inline]
    fn matches(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (PreParsedSuffix::V4(pref, bits), IpAddr::V4(v4)) => {
                suffix_bits_match(pref, &v4.octets(), *bits)
            }
            (PreParsedSuffix::V6(pref, bits), IpAddr::V6(v6)) => {
                suffix_bits_match(pref, &v6.octets(), *bits)
            }
            _ => false,
        }
    }
}

/// Compare the trailing `bits` bits of two equal-length address byte slices:
/// full bytes from the end plus a low-bit partial-byte check.
fn suffix_bits_match(pref_bytes: &[u8], ip_bytes: &[u8], bits: u32) -> bool {
    let size = ip_bytes.len();
    let full = (bits / 8) as usize;
    for i in 1..=full {
        if pref_bytes[size - i] != ip_bytes[size - i] {
            return false;
        }
    }
    let rem = bits % 8;
    if rem != 0 {
        let idx = size - full - 1;
        if pref_bytes[idx] << (8 - rem) != ip_bytes[idx] << (8 - rem) {
            return false;
        }
    }
    true
}

pub struct RuleEngine {
    rules: Vec<ParsedRule>,
    rule_stats: Vec<RuleStats>,
    geoip_matcher: geoip::GeoIpMatcher,
    geosite_matcher: geosite::GeoSiteMatcher,
    sub_rules: HashMap<String, Vec<ParsedRule>>,
    /// Per-provider load-time metadata, surfaced by the
    /// `/providers/rules` REST API. Captured at engine construction —
    /// runtime `PUT` reload is not supported (see api/rules_api.rs).
    provider_info: HashMap<String, RuleProviderInfo>,
    /// Per-provider domain lookup indexes for `rule-set:<name>` entries in
    /// `dns.fake-ip-filter` (mihomo config.go parseFakeIPRules). Built from
    /// the same parsed provider rules that RULE-SET expansion uses.
    provider_domain_indexes: HashMap<String, ProviderDomainIndex>,
}

/// Domain-only lookup index over one rule provider's payload, used by the
/// fake-ip-filter `rule-set:` bypass. Mirrors how the engine interprets
/// domain-behavior payloads (DOMAIN / DOMAIN-SUFFIX / DOMAIN-SUFFIX-STRICT)
/// plus the domain rule types of classical providers. Non-domain rules in a
/// classical provider are ignored, matching mihomo's "only matching domain
/// rules in fake-ip-filter" warning.
#[derive(Default)]
struct ProviderDomainIndex {
    exact: std::collections::HashSet<String>,
    /// "+.example.com" — matches example.com and any subdomain.
    suffix: std::collections::HashSet<String>,
    /// ".example.com" — matches subdomains only.
    strict_suffix: std::collections::HashSet<String>,
    /// "*.example.com" — matches exactly one extra label.
    star: std::collections::HashSet<String>,
    /// classical DOMAIN-KEYWORD payloads.
    keywords: Vec<String>,
}

impl ProviderDomainIndex {
    fn insert_rule(&mut self, rule: &ParsedRule) {
        let payload = rule.payload.to_lowercase();
        match rule.kind {
            RuleKind::Domain => {
                self.exact.insert(payload);
            }
            RuleKind::DomainSuffix => {
                self.suffix.insert(payload);
            }
            RuleKind::DomainSuffixStrict => {
                self.strict_suffix.insert(payload);
            }
            RuleKind::DomainStar => {
                self.star.insert(payload);
            }
            RuleKind::DomainKeyword => {
                self.keywords.push(payload);
            }
            _ => {}
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        if self.exact.contains(&domain) {
            return true;
        }
        if self.suffix.contains(&domain) {
            return true;
        }
        // Walk parent suffixes: for "a.b.example.com" check "b.example.com",
        // "example.com", "com" against the suffix sets.
        let mut first = true;
        let mut rest = domain.as_str();
        while let Some(idx) = rest.find('.') {
            rest = &rest[idx + 1..];
            if self.suffix.contains(rest) || self.strict_suffix.contains(rest) {
                return true;
            }
            // "*.x" matches exactly one extra label — only the first parent.
            if first && self.star.contains(rest) {
                return true;
            }
            first = false;
        }
        self.keywords.iter().any(|k| domain.contains(k.as_str()))
    }
}

/// Metadata for a rule provider as loaded into the engine.
///
/// `updated_at_unix` is the wall-clock seconds-since-epoch at which the
/// provider's rules were ingested. Because providers are consumed at
/// engine-construction time (their rules are merged into the engine's
/// indexes), this timestamp is effectively the config-load time.
#[derive(Debug, Clone)]
pub struct RuleProviderInfo {
    pub name: String,
    /// "HTTP" or "File" — matches mihomo's `vehicleType` field.
    pub vehicle_type: String,
    /// "domain", "ipcidr", or "classical".
    pub behavior: String,
    /// "yaml", "text", or "mrs".
    pub format: String,
    /// Number of rules ingested from this provider.
    pub rule_count: usize,
    /// Unix seconds when the provider was loaded.
    pub updated_at_unix: u64,
}

impl RuleEngine {
    pub async fn new(
        rule_strings: &[RuleString],
        providers: &HashMap<String, RuleProviderConfig>,
    ) -> Result<Self> {
        // Use default home directory when none is provided
        let home_dir = default_home_dir();
        Self::with_home_dir(rule_strings, providers, &home_dir).await
    }

    /// Create a new RuleEngine, loading GeoIP/GeoSite databases from `home_dir`.
    pub async fn with_home_dir(
        rule_strings: &[RuleString],
        providers: &HashMap<String, RuleProviderConfig>,
        home_dir: &Path,
    ) -> Result<Self> {
        Self::with_home_dir_geox(rule_strings, providers, home_dir, None).await
    }

    /// Like [`with_home_dir`], with the config's `geox-url` map for the
    /// geo-database auto-download (mihomo component/geodata/init.go — a rule
    /// referencing GEOIP/GEOSITE with no database on disk triggers a download
    /// before the engine is built).
    pub async fn with_home_dir_geox(
        rule_strings: &[RuleString],
        providers: &HashMap<String, RuleProviderConfig>,
        home_dir: &Path,
        geox_url: Option<&HashMap<String, String>>,
    ) -> Result<Self> {
        let mut rules = Vec::new();

        let referenced: String = rule_strings
            .iter()
            .map(|r| r.to_uppercase())
            .collect::<Vec<_>>()
            .join("\n");
        if referenced.contains("GEOIP") || referenced.contains("IP-ASN") {
            geodata::ensure_geoip(home_dir, geox_url).await;
        }
        if referenced.contains("GEOSITE") {
            geodata::ensure_geosite(home_dir, geox_url).await;
        }

        let geoip_matcher = geoip::GeoIpMatcher::new(home_dir);
        let geosite_matcher = geosite::GeoSiteMatcher::new(home_dir);

        // Provider payloads are ingested target-neutral; the target and the
        // no-resolve/src params come from each RULE-SET reference at expansion
        // time (mihomo compat: every RULE-SET is its own rule with its own
        // adapter and params, rules/provider/rule_set.go).
        let mut provider_rules: HashMap<String, Vec<ParsedRule>> = HashMap::new();
        let mut provider_info: HashMap<String, RuleProviderInfo> = HashMap::new();

        // Load rule providers and merge their rules into our indexes.
        for (name, prov_config) in providers {
            let path = prov_config.path.as_ref().map(|p| {
                let pb = PathBuf::from(p);
                if pb.is_relative() {
                    home_dir.join(pb)
                } else {
                    pb
                }
            });

            let behavior = prov_config.behavior.as_deref().unwrap_or("domain");
            let rp = provider::RuleProvider::new(
                name.clone(),
                &prov_config.provider_type,
                prov_config.url.clone(),
                path,
                prov_config.format.as_deref(),
                behavior,
            );

            let loaded_rules = match rp.load().await {
                Ok(rules) => rules,
                Err(e) => {
                    tracing::warn!("Failed to load rule provider '{}': {}", name, e);
                    continue;
                }
            };

            tracing::info!(
                "Loaded rule provider '{}' ({} behavior, {} rules)",
                name,
                behavior,
                loaded_rules.len()
            );

            // Capture metadata for the /providers/rules REST API. ruleCount
            // is the number of payload entries the provider parsed (the
            // parse_* helpers already strip blank/comment lines) — matches
            // what mihomo reports.
            let vehicle_type = match prov_config.provider_type.as_str() {
                "http" => "HTTP",
                "file" => "File",
                other => other,
            }
            .to_string();
            let updated_at_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            provider_info.insert(
                name.clone(),
                RuleProviderInfo {
                    name: name.clone(),
                    vehicle_type,
                    behavior: behavior.to_string(),
                    format: prov_config
                        .format
                        .clone()
                        .unwrap_or_else(|| "yaml".to_string()),
                    rule_count: loaded_rules.len(),
                    updated_at_unix,
                },
            );

            for payload in &loaded_rules {
                let payload = payload.trim();
                if payload.is_empty() || payload.starts_with('#') {
                    continue;
                }

                match behavior {
                    "domain" => {
                        // mihomo compat: domain_strategy.go + trie/domain.go
                        // "+.example.com" → match "example.com" AND "*.example.com" (DOMAIN-SUFFIX)
                        // ".example.com"  → match subdomains only (DOMAIN-SUFFIX-STRICT,
                        //                   synthetic type handled in matching)
                        // "*.example.com" → exactly ONE extra label (DOMAIN-STAR,
                        //                   synthetic — trie/domain.go wildcard node)
                        // "example.com"   → exact match only (DOMAIN)
                        let cleaned = payload.trim_start_matches("'").trim_end_matches("'");
                        let (rule_type, value) = if let Some(stripped) = cleaned.strip_prefix("+.")
                        {
                            ("DOMAIN-SUFFIX", stripped)
                        } else if let Some(stripped) = cleaned.strip_prefix('.') {
                            ("DOMAIN-SUFFIX-STRICT", stripped)
                        } else if let Some(stripped) = cleaned.strip_prefix("*.") {
                            ("DOMAIN-STAR", stripped)
                        } else {
                            ("DOMAIN", cleaned)
                        };
                        let value = value.to_lowercase();
                        if !value.is_empty() {
                            provider_rules.entry(name.clone()).or_default().push(
                                ParsedRule {
                                    rule_type: rule_type.to_string(),
                                    payload: value,
                                    ..Default::default()
                                }
                                .finalized(),
                            );
                        }
                    }
                    "ipcidr" => {
                        provider_rules.entry(name.clone()).or_default().push(
                            ParsedRule {
                                rule_type: "IP-CIDR".to_string(),
                                payload: payload.to_string(),
                                ..Default::default()
                            }
                            .finalized(),
                        );
                    }
                    "classical" => {
                        // mihomo compat: provider rules have no target — the target
                        // comes from the RULE-SET definition. Options like "no-resolve"
                        // go into params. ParseRulePayload(rule, needTarget=false).
                        if let Ok(parsed) = parse_provider_rule(payload) {
                            provider_rules.entry(name.clone()).or_default().push(parsed);
                        }
                    }
                    other => {
                        tracing::warn!("Unknown rule provider behavior '{}' for '{}'", other, name);
                    }
                }
            }
        }

        // Build per-provider domain indexes for the `rule-set:<name>` entries
        // of dns.fake-ip-filter (wired to the DNS resolver via
        // set_ruleset_checker, like the geosite checker).
        let mut provider_domain_indexes: HashMap<String, ProviderDomainIndex> = HashMap::new();
        for (name, parsed_rules) in &provider_rules {
            let mut index = ProviderDomainIndex::default();
            for r in parsed_rules {
                index.insert_rule(r);
            }
            provider_domain_indexes.insert(name.clone(), index);
        }

        for rule_str in rule_strings {
            let parsed = parse_rule(rule_str)?;

            // Warn only on rule types not present in mihomo's parser.go.
            // mihomo compat: full set as of Meta branch — `rules/parser.go`
            // case labels (lines 18-92).
            if !matches!(
                parsed.rule_type.as_str(),
                "DOMAIN"
                    | "DOMAIN-SUFFIX"
                    | "DOMAIN-KEYWORD"
                    | "DOMAIN-REGEX"
                    | "DOMAIN-WILDCARD"
                    | "GEOIP"
                    | "GEOSITE"
                    | "SRC-GEOIP"
                    | "IP-ASN"
                    | "SRC-IP-ASN"
                    | "SRC-ASN"
                    | "IP-CIDR"
                    | "IP-CIDR6"
                    | "SRC-IP-CIDR"
                    | "IP-SUFFIX"
                    | "SRC-IP-SUFFIX"
                    | "SRC-PORT"
                    | "DST-PORT"
                    | "IN-PORT"
                    | "DSCP"
                    | "PROCESS-NAME"
                    | "PROCESS-PATH"
                    | "PROCESS-NAME-REGEX"
                    | "PROCESS-PATH-REGEX"
                    | "PROCESS-NAME-WILDCARD"
                    | "PROCESS-PATH-WILDCARD"
                    | "NETWORK"
                    | "UID"
                    | "IN-TYPE"
                    | "IN-USER"
                    | "IN-NAME"
                    | "SUB-RULE"
                    | "AND"
                    | "OR"
                    | "NOT"
                    | "RULE-SET"
                    | "MATCH"
            ) {
                tracing::warn!("Unknown rule type: {}", parsed.rule_type);
            }

            // For RULE-SET: expand provider rules inline at this position.
            // mihomo compat: each RULE-SET reference is its own rule — the
            // same provider referenced twice with different targets expands
            // twice, and the reference's no-resolve/src params apply to every
            // expanded rule (rules/provider/rule_set.go NewRuleSet).
            if parsed.rule_type == "RULE-SET" {
                match provider_rules.get(&parsed.payload) {
                    Some(expanded) => {
                        for mut r in expanded.iter().cloned() {
                            r.target = parsed.target.clone();
                            for p in &parsed.params {
                                if !r.params.contains(p) {
                                    r.params.push(p.clone());
                                }
                            }
                            // The appended params change is_src/no_resolve.
                            rules.push(r.finalized());
                        }
                    }
                    None => {
                        if providers.contains_key(&parsed.payload) {
                            // Provider configured but failed to load — the
                            // provider-fetch policy is warn+skip, so the rule
                            // is dropped loudly rather than failing the boot.
                            tracing::error!(
                                "RULE-SET '{}' references provider that did not load; rule dropped",
                                parsed.payload
                            );
                        } else {
                            // mihomo compat: unknown rule-set name fails the
                            // config load (rules/provider/rule_set.go).
                            return Err(anyhow::anyhow!("not found rule-set: {}", parsed.payload));
                        }
                    }
                }
                // Don't push the RULE-SET rule itself — it's been expanded
            } else {
                rules.push(parsed);
            }
        }

        // Log the first 20 rules for debugging rule order
        tracing::info!("Rule engine: {} total sequential rules", rules.len());
        for (i, rule) in rules.iter().take(20).enumerate() {
            tracing::info!(
                "  Rule[{}]: {},{},{}",
                i,
                rule.rule_type,
                rule.payload,
                rule.target
            );
        }
        if rules.len() > 20 {
            tracing::info!("  ... ({} more rules)", rules.len() - 20);
        }

        let rule_stats: Vec<RuleStats> = (0..rules.len())
            .map(|_| RuleStats {
                hit_count: AtomicU64::new(0),
                disabled: AtomicBool::new(false),
            })
            .collect();

        Ok(Self {
            rules,
            rule_stats,
            geoip_matcher,
            geosite_matcher,
            sub_rules: HashMap::new(),
            provider_info,
            provider_domain_indexes,
        })
    }

    /// Per-provider load-time metadata, keyed by provider name.
    /// Used by the `/providers/rules` REST API.
    pub fn provider_info(&self) -> &HashMap<String, RuleProviderInfo> {
        &self.provider_info
    }

    /// Check `domain` against the domain rules of the named rule provider.
    /// Used by `rule-set:<name>` entries in dns.fake-ip-filter. Returns false
    /// for unknown providers (mihomo fails config load in that case —
    /// miemietron logs at wiring time and keeps the entry inert).
    pub fn provider_domain_match(&self, provider: &str, domain: &str) -> bool {
        self.provider_domain_indexes
            .get(provider)
            .is_some_and(|idx| idx.matches(domain))
    }

    /// Whether a rule provider with this name was loaded into the engine.
    pub fn has_provider(&self, provider: &str) -> bool {
        self.provider_info.contains_key(provider)
    }

    /// Set sub-rules from config. Called after construction.
    pub fn set_sub_rules(&mut self, sub_rules_config: &HashMap<String, Vec<RuleString>>) {
        for (name, rule_strings) in sub_rules_config {
            let parsed: Vec<ParsedRule> = rule_strings
                .iter()
                .filter_map(|s| parse_rule(s.trim()).ok())
                .collect();
            if !parsed.is_empty() {
                self.sub_rules.insert(name.clone(), parsed);
            }
        }
    }

    /// Match a connection and return (action, rule_type, rule_payload).
    ///
    /// This is used by the connection manager to populate the `rule` and
    /// `rulePayload` fields in the connections API.
    pub fn match_rules_detailed(&self, metadata: &RuleMetadata) -> (Action, String, String) {
        self.match_rules_detailed_filtered(metadata, None)
    }

    /// Like [`match_rules_detailed`], with an optional adapter filter.
    ///
    /// mihomo compat: tunnel.go `match()` skips a matched rule when the
    /// resolved adapter can't serve the connection (`metadata.NetWork == UDP
    /// && !adapter.SupportUDP()`) and keeps evaluating later rules, so UDP
    /// traffic falls through to e.g. `GEOIP,CN,DIRECT` or `MATCH` instead of
    /// being dropped. The UDP path passes a closure returning whether the
    /// matched action's adapter supports UDP.
    pub fn match_rules_detailed_filtered(
        &self,
        metadata: &RuleMetadata,
        adapter_ok: Option<&dyn Fn(&Action) -> bool>,
    ) -> (Action, String, String) {
        // Pre-lowercase domain once for all domain-based rules.
        // Previously each domain rule arm called to_lowercase() individually,
        // resulting in 5+ allocations per connection through the rule chain.
        let domain_lower = metadata.domain.as_ref().map(|d| d.to_lowercase());

        for (i, rule) in self.rules.iter().enumerate() {
            // mihomo compat: skip disabled rules (toggled via PATCH /rules/disable)
            if self
                .rule_stats
                .get(i)
                .is_some_and(|s| s.disabled.load(Ordering::Relaxed))
            {
                continue;
            }

            if let Some(action) = self.match_single_rule(rule, metadata, domain_lower.as_deref()) {
                if let Some(check) = adapter_ok {
                    if !check(&action) {
                        continue;
                    }
                }
                if let Some(stats) = self.rule_stats.get(i) {
                    stats.hit_count.fetch_add(1, Ordering::Relaxed);
                }
                return (action, rule.rule_type.clone(), rule.payload.clone());
            }
        }

        // mihomo compat: no rule matched → DIRECT with a nil rule
        // (tunnel.go:685). The empty rule type distinguishes this from an
        // explicit MATCH rule in /connections and the info log
        // ("doesn't match any rule using ...").
        (Action::Direct, String::new(), String::new())
    }

    /// Match a connection against the rule engine and return the action.
    pub fn match_rules(&self, metadata: &RuleMetadata) -> Action {
        self.match_rules_detailed(metadata).0
    }

    /// Whether rule evaluation needs the destination host resolved to a real IP.
    ///
    /// mihomo compat: tunnel.go `match()` resolves the host on demand (lazily)
    /// the first time it reaches a destination-IP rule (GEOIP / IP-CIDR /
    /// IP-CIDR6 / IP-SUFFIX / IP-ASN, without `no-resolve`) while `DstIP` is
    /// empty. Earlier rules that match without the IP (DOMAIN*, PROCESS*, ...)
    /// short-circuit, so no resolution happens for them.
    ///
    /// The caller invokes this only when `metadata.dst_ip` is None and a domain
    /// is known (FakeIP was blanked from `dst_ip`); it then resolves via
    /// `DnsResolver::resolve_real_ip`, populates `dst_ip`, and re-runs
    /// `match_rules_detailed`. Without this, `GEOIP,CN,DIRECT` never matches
    /// domain traffic under fake-ip and domestic connections leak through the
    /// proxy catch-all.
    pub fn needs_ip_resolution(&self, metadata: &RuleMetadata) -> bool {
        let domain_lower = metadata.domain.as_ref().map(|d| d.to_lowercase());
        for (i, rule) in self.rules.iter().enumerate() {
            // mihomo compat: skip disabled rules (toggled via PATCH /rules/disable)
            if self
                .rule_stats
                .get(i)
                .is_some_and(|s| s.disabled.load(Ordering::Relaxed))
            {
                continue;
            }
            // First destination-IP rule reached before any match → resolve once.
            if self.rule_wants_dst_resolution(rule, 0) {
                return true;
            }
            // An earlier rule matches without needing the dst IP → no resolution.
            if self
                .match_single_rule(rule, metadata, domain_lower.as_deref())
                .is_some()
            {
                return false;
            }
        }
        false
    }

    /// mihomo compat: `Rule.Match(metadata)` — evaluate one parsed rule.
    ///
    /// Dispatch is on the precomputed [`RuleKind`] discriminant (one compare per
    /// rule instead of a 36-arm string match) and routes to a per-family
    /// matcher. Every family except logic answers a plain bool, so the
    /// `target -> Action` mapping happens once here.
    fn match_single_rule(
        &self,
        rule: &ParsedRule,
        metadata: &RuleMetadata,
        domain_lower: Option<&str>,
    ) -> Option<Action> {
        use RuleKind::*;
        let matched = match rule.kind {
            Match => true,

            Network => metadata.network.eq_ignore_ascii_case(&rule.payload),

            Domain | DomainSuffix | DomainSuffixStrict | DomainStar | DomainKeyword
            | DomainWildcard | DomainRegex | GeoSite => self.match_domain_rule(rule, domain_lower),

            GeoIp | SrcGeoIp | IpCidr | SrcIpCidr | IpSuffix | SrcIpSuffix | IpAsn | SrcIpAsn => {
                self.match_ip_rule(rule, metadata)
            }

            SrcPort | DstPort | InPort => self.match_port_rule(rule, metadata),

            ProcessName | ProcessPath | ProcessNameRegex | ProcessPathRegex
            | ProcessNameWildcard | ProcessPathWildcard => self.match_process_rule(rule, metadata),

            InType | InUser | InName | Uid | Dscp => self.match_inbound_rule(rule, metadata),

            // Logic rules pick their own target (SUB-RULE resolves to the
            // matched rule *inside* the named group), so they answer directly.
            And | Or | Not | SubRule => return self.match_logic_rule(rule, metadata, domain_lower),

            Unknown => false,
        };

        if matched {
            Some(target_to_action(&rule.target))
        } else {
            None
        }
    }

    /// DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX /
    /// DOMAIN-WILDCARD / GEOSITE plus the two provider-only suffix forms.
    /// The payload was lowercased at parse time, as was `domain_lower`.
    fn match_domain_rule(&self, rule: &ParsedRule, domain_lower: Option<&str>) -> bool {
        let Some(d) = domain_lower else {
            return false;
        };
        let s = rule.payload.as_str();
        match rule.kind {
            RuleKind::Domain => d == s,

            RuleKind::DomainSuffix => d == s || is_subdomain_of(d, s),

            // mihomo compat: ".example.com" in domain-behavior providers
            // matches subdomains only (not the domain itself)
            RuleKind::DomainSuffixStrict => is_subdomain_of(d, s),

            // mihomo compat: "*.example.com" in domain-behavior providers —
            // exactly one extra label (trie/domain.go wildcard node).
            RuleKind::DomainStar => {
                d.len() > s.len() + 1
                    && is_subdomain_of(d, s)
                    && !d[..d.len() - s.len() - 1].contains('.')
            }

            RuleKind::DomainKeyword => d.contains(s),

            RuleKind::DomainWildcard => wildcard_match(s, d),

            // Pre-compiled at parse time (avoids Regex::new per match). Only
            // patterns that failed to compile take the fallback, and they fail
            // again there → no match.
            RuleKind::DomainRegex => match &rule.prepared {
                Prepared::Regex(re) => re.is_match(d),
                _ => match_domain_regex(s, d),
            },

            RuleKind::GeoSite => self.geosite_matcher.lookup(d, s),

            _ => false,
        }
    }

    /// GEOIP / IP-CIDR / IP-SUFFIX / IP-ASN and their SRC- variants.
    fn match_ip_rule(&self, rule: &ParsedRule, metadata: &RuleMetadata) -> bool {
        // mihomo compat: the `src` param flips a destination-IP rule onto the
        // source IP (base.go ParseParams; parser.go NewGEOIP(isSrc)); the SRC-*
        // rule types always read the source IP.
        let ip = match rule.kind {
            RuleKind::SrcGeoIp
            | RuleKind::SrcIpCidr
            | RuleKind::SrcIpSuffix
            | RuleKind::SrcIpAsn => metadata.src_ip.as_ref(),
            _ if rule.is_src => metadata.src_ip.as_ref(),
            _ => metadata.dst_ip.as_ref(),
        };
        let Some(ip) = ip else {
            return false;
        };
        match rule.kind {
            RuleKind::GeoIp | RuleKind::SrcGeoIp => self.geoip_payload_matches(ip, &rule.payload),

            RuleKind::IpAsn | RuleKind::SrcIpAsn => self.asn_payload_matches(ip, rule),

            // Pre-parsed at load time for an O(1) bitwise match; the string
            // fallback only runs for a payload that failed to parse.
            RuleKind::IpCidr | RuleKind::SrcIpCidr => match &rule.prepared {
                Prepared::Cidr(cidr) => cidr.matches(ip),
                _ => check_ip_in_cidr(ip, &rule.payload),
            },

            RuleKind::IpSuffix | RuleKind::SrcIpSuffix => match &rule.prepared {
                Prepared::Suffix(suffix) => suffix.matches(ip),
                _ => check_ip_suffix(ip, &rule.payload),
            },

            _ => false,
        }
    }

    /// SRC-PORT / DST-PORT / IN-PORT — all three share one range-list payload.
    fn match_port_rule(&self, rule: &ParsedRule, metadata: &RuleMetadata) -> bool {
        let port = match rule.kind {
            RuleKind::SrcPort => Some(metadata.src_port),
            RuleKind::DstPort => Some(metadata.dst_port),
            RuleKind::InPort => metadata.in_port,
            _ => None,
        };
        let Some(port) = port else {
            return false;
        };
        match &rule.prepared {
            Prepared::Ports(ranges) => port_matches_pre(port, ranges),
            _ => port_matches(port, &rule.payload),
        }
    }

    /// PROCESS-NAME / PROCESS-PATH and their -REGEX / -WILDCARD variants.
    fn match_process_rule(&self, rule: &ParsedRule, metadata: &RuleMetadata) -> bool {
        let value = match rule.kind {
            RuleKind::ProcessName | RuleKind::ProcessNameRegex | RuleKind::ProcessNameWildcard => {
                metadata.process_name.as_deref()
            }
            RuleKind::ProcessPath | RuleKind::ProcessPathRegex | RuleKind::ProcessPathWildcard => {
                metadata.process_path.as_deref()
            }
            _ => None,
        };
        let Some(value) = value else {
            return false;
        };
        match rule.kind {
            // mihomo compat: process.go uses strings.EqualFold (case-insensitive)
            RuleKind::ProcessName | RuleKind::ProcessPath => {
                value.eq_ignore_ascii_case(&rule.payload)
            }

            // mihomo compat: process.go:45-47 uses regexp2 with IgnoreCase.
            RuleKind::ProcessNameRegex | RuleKind::ProcessPathRegex => {
                matches!(&rule.prepared, Prepared::Regex(re) if re.is_match(value))
            }

            // mihomo compat: process.go lowercases both pattern and target
            _ => wildcard_match(&rule.payload.to_lowercase(), &value.to_lowercase()),
        }
    }

    /// IN-TYPE / IN-USER / IN-NAME plus the socket attributes UID and DSCP.
    fn match_inbound_rule(&self, rule: &ParsedRule, metadata: &RuleMetadata) -> bool {
        match rule.kind {
            // mihomo compat: payload is a `/`-separated list, matched
            // case-insensitively; `SOCKS` expands to SOCKS4+SOCKS5
            // (in_type.go parseInTypes).
            RuleKind::InType => metadata.in_type.is_some_and(|in_type| {
                rule.payload.split('/').any(|tp| {
                    let tp = tp.trim();
                    tp.eq_ignore_ascii_case(in_type)
                        || (tp.eq_ignore_ascii_case("socks")
                            && (in_type.eq_ignore_ascii_case("socks4")
                                || in_type.eq_ignore_ascii_case("socks5")))
                })
            }),

            // mihomo compat: in_user.go / in_name.go — '/'-separated lists.
            RuleKind::InUser => metadata
                .in_user
                .as_ref()
                .is_some_and(|v| rule.payload.split('/').any(|u| u.trim() == v)),

            RuleKind::InName => metadata
                .in_name
                .as_ref()
                .is_some_and(|v| rule.payload.split('/').any(|n| n.trim() == v)),

            // mihomo compat: uid.go / dscp.go — the payload is a range list
            // ("1000-1100/2000") and IntRanges.Check(empty) is true, so "*"
            // matches everything.
            RuleKind::Uid | RuleKind::Dscp => {
                let value = if rule.kind == RuleKind::Uid {
                    metadata.uid
                } else {
                    metadata.dscp.map(u32::from)
                };
                let Some(value) = value else {
                    return false;
                };
                match &rule.prepared {
                    Prepared::Ranges(ranges) => u32_ranges_check(value, ranges),
                    _ => parse_u32_ranges(&rule.payload)
                        .map(|r| u32_ranges_check(value, &r))
                        .unwrap_or(false),
                }
            }

            _ => false,
        }
    }

    /// mihomo compat: logic.go Match — sub-rules were parsed through the full
    /// rule parser at load, so every rule type (including nested logic)
    /// evaluates with the real matcher. AND over zero rules is vacuously true;
    /// OR over zero rules is false.
    fn match_logic_rule(
        &self,
        rule: &ParsedRule,
        metadata: &RuleMetadata,
        domain_lower: Option<&str>,
    ) -> Option<Action> {
        match rule.kind {
            RuleKind::And => rule
                .sub_rules
                .iter()
                .all(|r| self.match_single_rule(r, metadata, domain_lower).is_some())
                .then(|| target_to_action(&rule.target)),

            RuleKind::Or => rule
                .sub_rules
                .iter()
                .any(|r| self.match_single_rule(r, metadata, domain_lower).is_some())
                .then(|| target_to_action(&rule.target)),

            RuleKind::Not => self
                .match_single_rule(rule.sub_rules.first()?, metadata, domain_lower)
                .is_none()
                .then(|| target_to_action(&rule.target)),

            // mihomo compat: logic.go — the payload is ONE gating condition and
            // the target is the sub-rule group name. Only when the condition
            // matches is the named group evaluated.
            RuleKind::SubRule => {
                let cond = rule.sub_rules.first()?;
                self.match_single_rule(cond, metadata, domain_lower)?;
                self.match_sub_rules_group(&rule.target, metadata, domain_lower, 0)
            }

            _ => None,
        }
    }

    /// mihomo compat: logic.go `matchSubRules` — walk the named sub-rule
    /// group; nested SUB-RULE entries recurse (depth-capped so a cyclic group
    /// definition can't overflow the stack under panic=abort); a matched
    /// "PASS-RULE" target skips to the next rule in the group.
    fn match_sub_rules_group(
        &self,
        name: &str,
        metadata: &RuleMetadata,
        domain_lower: Option<&str>,
        depth: usize,
    ) -> Option<Action> {
        if depth > 16 {
            return None;
        }
        let rules = self.sub_rules.get(name)?;
        for sub in rules {
            let action = if sub.kind == RuleKind::SubRule {
                let Some(cond) = sub.sub_rules.first() else {
                    continue;
                };
                if self
                    .match_single_rule(cond, metadata, domain_lower)
                    .is_some()
                {
                    self.match_sub_rules_group(&sub.target, metadata, domain_lower, depth + 1)
                } else {
                    None
                }
            } else {
                self.match_single_rule(sub, metadata, domain_lower)
            };
            if let Some(action) = action {
                if matches!(&action, Action::Proxy(n) if n == "PASS-RULE") {
                    continue;
                }
                return Some(action);
            }
        }
        None
    }

    /// Shared GEOIP / SRC-GEOIP payload check against one IP.
    /// mihomo compat: the "lan" pseudo-country matches private/reserved IPs
    /// without an mmdb lookup (geoip.go:105-107,154-162); Meta-geoip0 records
    /// can carry multiple codes and match if ANY equals the payload
    /// (geoip.go:87-93).
    fn geoip_payload_matches(&self, ip: &IpAddr, payload: &str) -> bool {
        if payload.eq_ignore_ascii_case("lan") {
            return ip_is_lan(ip);
        }
        self.geoip_matcher
            .lookup_codes(ip)
            .iter()
            .any(|c| c.eq_ignore_ascii_case(payload))
    }

    /// Shared IP-ASN / SRC-IP-ASN payload check against one IP.
    fn asn_payload_matches(&self, ip: &IpAddr, rule: &ParsedRule) -> bool {
        let Some(asn) = self.geoip_matcher.lookup_asn(ip) else {
            return false;
        };
        let rule_asn = match &rule.prepared {
            Prepared::Asn(v) => Some(*v),
            _ => rule.payload.parse().ok(),
        };
        rule_asn == Some(asn)
    }

    /// mihomo compat: `C.Rule.ShouldResolveIP()` — destination-IP rules
    /// resolve the host on demand unless tagged `no-resolve` (or `src`, which
    /// implies it). Logic rules resolve if any nested rule would (mihomo
    /// resolves lazily inside the nested Match via the helper); SUB-RULE
    /// considers both its condition and the referenced group.
    fn rule_wants_dst_resolution(&self, rule: &ParsedRule, depth: usize) -> bool {
        if depth > 16 {
            return false;
        }
        match rule.kind {
            RuleKind::GeoIp | RuleKind::IpCidr | RuleKind::IpSuffix | RuleKind::IpAsn => {
                !rule.is_src && !rule.no_resolve
            }
            RuleKind::And | RuleKind::Or | RuleKind::Not => rule
                .sub_rules
                .iter()
                .any(|r| self.rule_wants_dst_resolution(r, depth + 1)),
            RuleKind::SubRule => {
                rule.sub_rules
                    .iter()
                    .any(|r| self.rule_wants_dst_resolution(r, depth + 1))
                    || self.sub_rules.get(&rule.target).is_some_and(|rs| {
                        rs.iter()
                            .any(|r| self.rule_wants_dst_resolution(r, depth + 1))
                    })
            }
            _ => false,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> &[ParsedRule] {
        &self.rules
    }

    /// Access per-rule hit statistics (parallel to `rules()`).
    pub fn rule_stats(&self) -> &[RuleStats] {
        &self.rule_stats
    }

    /// Get a reference to the GeoIP matcher (for DNS fallback filtering, etc.)
    pub fn geoip_matcher(&self) -> &geoip::GeoIpMatcher {
        &self.geoip_matcher
    }

    /// Get a reference to the GeoSite matcher (for DNS fake-ip-filter bypass).
    pub fn geosite_matcher(&self) -> &geosite::GeoSiteMatcher {
        &self.geosite_matcher
    }

    /// Get the record size for a GEOIP or GEOSITE rule.
    /// mihomo compat: matches RuleGroup.GetRecodeSize() in the API.
    /// Returns -1 for non-geo rules.
    pub fn rule_record_size(&self, rule_type: &str, payload: &str) -> i64 {
        match rule_type {
            "GEOIP" | "SRC-GEOIP" => {
                // mihomo compat: "lan" pseudorule has size 0
                if payload.eq_ignore_ascii_case("lan") {
                    0
                } else {
                    // maxminddb doesn't expose per-country record counts easily;
                    // return 0 to indicate loaded but unknown count.
                    if self.geoip_matcher.is_loaded() {
                        0
                    } else {
                        -1
                    }
                }
            }
            "GEOSITE" => self.geosite_matcher.record_count(payload) as i64,
            _ => -1,
        }
    }
}

/// Parse a rule from the main config (needTarget=true).
/// Format: "TYPE,PAYLOAD,TARGET[,PARAMS...]" or "MATCH,TARGET"
fn parse_rule(rule_str: &str) -> Result<ParsedRule> {
    parse_rule_payload(rule_str, true)
}

/// Parse a rule from a provider file (needTarget=false).
/// Format: "TYPE,PAYLOAD[,PARAMS...]" — no target.
/// mihomo compat: ParseRulePayload(rule, false) puts everything after payload into params.
fn parse_provider_rule(rule_str: &str) -> Result<ParsedRule> {
    parse_rule_payload(rule_str, false)
}

/// Core rule parser matching mihomo's ParseRulePayload(ruleRaw, needTarget)
/// (`rules/common/base.go:46-79`) plus the per-type validation mihomo does in
/// the rule constructors (`rules/parser.go` ParseRule) — invalid payloads fail
/// the config load instead of becoming silently inert rules.
fn parse_rule_payload(rule_str: &str, need_target: bool) -> Result<ParsedRule> {
    let trimmed = rule_str.trim();

    let items: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
    let rule_type = items[0].to_uppercase();

    if items.len() == 1 {
        return Err(anyhow::anyhow!("invalid rule format: {rule_str}"));
    }

    // MATCH rule: "MATCH,target" — no payload, no params.
    if rule_type == "MATCH" {
        return Ok(ParsedRule {
            rule_type,
            target: items[1].to_string(),
            ..Default::default()
        }
        .finalized());
    }

    let mut rule = match rule_type.as_str() {
        // mihomo compat (base.go:54-61): these payloads contain commas and
        // take no params — the target is the LAST comma item, the payload is
        // the rejoined middle. `DOMAIN-REGEX,^a{1,3}\.com$,Proxy` works.
        "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" | "PROCESS-NAME-REGEX"
        | "PROCESS-PATH-REGEX" => {
            let (payload_items, target) = if need_target {
                (&items[1..items.len() - 1], items[items.len() - 1])
            } else {
                (&items[1..], "")
            };
            ParsedRule {
                rule_type: rule_type.clone(),
                payload: payload_items.join(","),
                target: target.to_string(),
                ..Default::default()
            }
        }
        _ => {
            let payload = items[1].to_string();
            let (target, params) = if items.len() > 2 {
                if need_target {
                    // Main config: item[2] = target, item[3..] = params
                    (
                        items[2].to_string(),
                        items[3..].iter().map(|s| s.to_string()).collect(),
                    )
                } else {
                    // Provider rule: no target, item[2..] = params (e.g. "no-resolve")
                    (
                        String::new(),
                        items[2..].iter().map(|s| s.to_string()).collect(),
                    )
                }
            } else {
                (String::new(), vec![])
            };
            ParsedRule {
                rule_type: rule_type.clone(),
                payload,
                target,
                params,
                ..Default::default()
            }
        }
    };

    // Per-type construction/validation, mirroring mihomo's rule constructors.
    match rule.rule_type.as_str() {
        // Pre-lowercase domain payloads (NOT regex — regex uses (?i) flag).
        // mihomo compat: domain_wildcard.go:35 lowercases the pattern too.
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-WILDCARD" => {
            rule.payload = rule.payload.to_lowercase();
        }

        // mihomo compat: logic.go NewAND/NewOR/NewNOT parse each top-level
        // parenthesized sub-payload through the full rule parser.
        "AND" | "OR" => {
            rule.sub_rules = parse_logic_sub_rules(&rule.payload)?;
        }
        "NOT" => {
            rule.sub_rules = parse_logic_sub_rules(&rule.payload)?;
            if rule.sub_rules.len() != 1 {
                return Err(anyhow::anyhow!("not rule must contain one rule"));
            }
        }
        // mihomo compat: SUB-RULE payload is ONE gating condition; the target
        // is the sub-rule group name (logic.go NewSubRule wraps in parens).
        "SUB-RULE" => {
            rule.sub_rules = parse_logic_sub_rules(&format!("({})", rule.payload))?;
            if rule.sub_rules.len() != 1 {
                return Err(anyhow::anyhow!("Sub-Rule rule must contain one rule"));
            }
        }

        // mihomo compat: port.go NewPort errors on invalid/empty specs.
        "SRC-PORT" | "DST-PORT" | "IN-PORT" => {
            let ranges = parse_port_ranges(&rule.payload)
                .map_err(|e| anyhow::anyhow!("payloadRule error: {e}"))?;
            if ranges.is_empty() {
                return Err(anyhow::anyhow!("payloadRule error: empty port ranges"));
            }
        }

        // mihomo compat: uid.go errors on invalid/empty ranges.
        "UID" => {
            let ranges = parse_u32_ranges(&rule.payload)
                .map_err(|e| anyhow::anyhow!("payloadRule error: {e}"))?;
            if ranges.is_empty() {
                return Err(anyhow::anyhow!("payloadRule error: empty uid ranges"));
            }
        }

        // mihomo compat: dscp.go — "*" is allowed (matches all), values > 63 error.
        "DSCP" => {
            let ranges = parse_u32_ranges(&rule.payload)
                .map_err(|e| anyhow::anyhow!("parse DSCP rule fail: {e}"))?;
            if ranges.iter().any(|&(_, end)| end > 63) {
                return Err(anyhow::anyhow!("DSCP couldn't be negative or exceed 63"));
            }
        }

        // mihomo compat: in_user.go / in_name.go — empty list entries error.
        "IN-USER" | "IN-NAME" => {
            if rule.payload.split('/').any(|s| s.trim().is_empty()) {
                return Err(anyhow::anyhow!("in user couldn't be empty"));
            }
        }

        // mihomo compat: ipcidr.go / ipsuffix.go — netip.ParsePrefix errors
        // fail the config load.
        "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" => {
            if PreParsedCidr::parse(&rule.payload).is_none() {
                return Err(anyhow::anyhow!("payloadRule error: {}", rule.payload));
            }
        }
        "IP-SUFFIX" | "SRC-IP-SUFFIX" => {
            if PreParsedSuffix::parse(&rule.payload).is_none() {
                return Err(anyhow::anyhow!("payloadRule error: {}", rule.payload));
            }
        }

        _ => {}
    }

    // After the per-type payload normalisation above (domain lowercasing), so
    // the prepared matchers see the final payload.
    Ok(rule.finalized())
}

/// mihomo compat: logic.go `parsePayload`/`format`/`findSubRuleRange` — the
/// payload must be `(...)`-wrapped; collect every balanced range, skip the one
/// covering the whole payload, and keep the outermost of the rest. Each kept
/// sub-payload goes through the full rule parser with needTarget=false. MATCH
/// and SUB-RULE are rejected inside logic rules (logic.go payloadToRule).
fn parse_logic_sub_rules(payload: &str) -> Result<Vec<ParsedRule>> {
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err(anyhow::anyhow!("payload format error"));
    }

    // format(): all balanced ranges, byte offsets, sorted by start.
    let mut stack: Vec<usize> = Vec::new();
    let mut all_ranges: Vec<(usize, usize)> = Vec::new();
    for (i, ch) in payload.char_indices() {
        match ch {
            '(' => stack.push(i),
            ')' => {
                let start = stack.pop().ok_or_else(|| anyhow::anyhow!("missing '('"))?;
                all_ranges.push((start, i));
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(anyhow::anyhow!("format error is missing )"));
    }
    all_ranges.sort_by_key(|&(s, _)| s);

    // findSubRuleRange(): skip the whole-payload range; keep ranges not
    // strictly contained in an already-kept range (parents come first).
    let whole = (0usize, payload.len() - 1);
    let mut kept: Vec<(usize, usize)> = Vec::new();
    for &(s, e) in &all_ranges {
        if (s, e) == whole {
            continue;
        }
        if kept.iter().any(|&(ks, ke)| ks < s && ke > e) {
            continue;
        }
        kept.push((s, e));
    }

    let mut subs = Vec::with_capacity(kept.len());
    for (s, e) in kept {
        let sub_payload = &payload[s + 1..e];
        let sub = parse_rule_payload(sub_payload, false)
            .map_err(|_| anyhow::anyhow!("[{sub_payload}] format is error"))?;
        if sub.rule_type == "MATCH" || sub.rule_type == "SUB-RULE" {
            return Err(anyhow::anyhow!(
                "unsupported rule type [{}] on logic rule",
                sub.rule_type
            ));
        }
        subs.push(sub);
    }
    Ok(subs)
}

#[inline]
fn target_to_action(target: &str) -> Action {
    match target {
        "DIRECT" => Action::Direct,
        "REJECT" => Action::Reject,
        "REJECT-DROP" => Action::RejectDrop,
        name => Action::Proxy(name.to_string()),
    }
}

/// mihomo compat: map miemietron's config-syntax rule type (e.g.
/// `DOMAIN-SUFFIX`, `GEOIP`, `RULE-SET`, `MATCH`) to mihomo's
/// `RuleType.String()` display form (`DomainSuffix`, `GeoIP`, `RuleSet`,
/// `Match`), which dashboards and `GET /rules` / `/connections` expect
/// (`constant/rule.go`). Unknown types pass through unchanged.
pub fn rule_type_display(rule_type: &str) -> &str {
    match rule_type {
        "DOMAIN" => "Domain",
        "DOMAIN-SUFFIX" => "DomainSuffix",
        "DOMAIN-KEYWORD" => "DomainKeyword",
        "DOMAIN-REGEX" => "DomainRegex",
        "DOMAIN-WILDCARD" => "DomainWildcard",
        "GEOSITE" => "GeoSite",
        "GEOIP" => "GeoIP",
        "SRC-GEOIP" => "SrcGeoIP",
        "IP-ASN" => "IPASN",
        "SRC-IP-ASN" => "SrcIPASN",
        "IP-CIDR" | "IP-CIDR6" => "IPCIDR",
        "SRC-IP-CIDR" => "SrcIPCIDR",
        "IP-SUFFIX" => "IPSuffix",
        "SRC-IP-SUFFIX" => "SrcIPSuffix",
        "SRC-PORT" => "SrcPort",
        "DST-PORT" => "DstPort",
        "IN-PORT" => "InPort",
        "IN-USER" => "InUser",
        "IN-NAME" => "InName",
        "IN-TYPE" => "InType",
        "PROCESS-NAME" => "ProcessName",
        "PROCESS-PATH" => "ProcessPath",
        "PROCESS-NAME-REGEX" => "ProcessNameRegex",
        "PROCESS-PATH-REGEX" => "ProcessPathRegex",
        "PROCESS-NAME-WILDCARD" => "ProcessNameWildcard",
        "PROCESS-PATH-WILDCARD" => "ProcessPathWildcard",
        "MATCH" => "Match",
        "RULE-SET" => "RuleSet",
        "NETWORK" => "Network",
        "DSCP" => "DSCP",
        "UID" => "Uid",
        "SUB-RULE" => "SubRules",
        "AND" => "AND",
        "OR" => "OR",
        "NOT" => "NOT",
        other => other,
    }
}

/// mihomo compat: `GEOIP.isLan` (`rules/common/geoip.go:154-162`) — the "lan"
/// pseudo-country matches private, unspecified, loopback, multicast and
/// link-local addresses without consulting the mmdb. (mihomo also treats the
/// fake-ip broadcast address as LAN; that pool-specific case is not reproduced
/// here since the rule engine has no fakeip handle.)
fn ip_is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        }
    }
}

/// mihomo compat: unsigned range-list parser (`common/utils/ranges.go`
/// newIntRanges + `range.go` newIntRange). "" and "*" yield an empty list
/// (`IntRanges.Check` treats empty as match-all); ',' is normalized to '/';
/// at most 28 ranges; "a-b" with inverted bounds is swapped (NewRange); Go's
/// `T(val)` conversion truncates, so out-of-range values wrap like mihomo.
fn parse_unsigned_ranges(spec: &str, bits: u32) -> Result<Vec<(u64, u64)>> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" {
        return Ok(vec![]);
    }
    let normalized = spec.replace(',', "/");
    let parts: Vec<&str> = normalized.split('/').collect();
    if parts.len() > 28 {
        return Err(anyhow::anyhow!(
            "intRanges error, too many ranges to use, maximum support 28 ranges"
        ));
    }
    let mask: u64 = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let parse_one = |s: &str| -> Result<u64> {
        s.trim_matches(|c| c == '[' || c == ']' || c == ' ')
            .parse::<u64>()
            .map(|v| v & mask)
            .map_err(|_| anyhow::anyhow!("invalid range: {s}"))
    };
    let mut ranges = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let seg: Vec<&str> = part.split('-').collect();
        match seg.len() {
            1 => {
                let v = parse_one(seg[0])?;
                ranges.push((v, v));
            }
            2 => {
                let a = parse_one(seg[0])?;
                let b = parse_one(seg[1])?;
                ranges.push(if a > b { (b, a) } else { (a, b) });
            }
            _ => return Err(anyhow::anyhow!("invalid range: {part}")),
        }
    }
    Ok(ranges)
}

/// Parse a port spec ("80", "80/443", "1000-2000", combined) into ranges.
/// mihomo compat: port.go NewPort errors on invalid or empty specs.
fn parse_port_ranges(spec: &str) -> Result<Vec<(u16, u16)>> {
    Ok(parse_unsigned_ranges(spec, 16)?
        .into_iter()
        .map(|(a, b)| (a as u16, b as u16))
        .collect())
}

/// Parse a u32 range spec (UID / DSCP rules).
fn parse_u32_ranges(spec: &str) -> Result<Vec<(u32, u32)>> {
    Ok(parse_unsigned_ranges(spec, 32)?
        .into_iter()
        .map(|(a, b)| (a as u32, b as u32))
        .collect())
}

/// Check if a port matches a mihomo-style port spec. Used for rules without a
/// pre-parsed index (logic sub-rules). mihomo compat: `IntRanges.Check` —
/// empty ranges match everything; an unparseable spec never matches (the main
/// config path rejects it at load).
fn port_matches(port: u16, spec: &str) -> bool {
    match parse_port_ranges(spec) {
        Ok(ranges) if ranges.is_empty() => true,
        Ok(ranges) => port_matches_pre(port, &ranges),
        Err(_) => false,
    }
}

/// Fast port matching against pre-parsed ranges (avoids re-parsing per match).
#[inline]
fn port_matches_pre(port: u16, ranges: &[(u16, u16)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| port >= start && port <= end)
}

/// mihomo compat: `IntRanges.Check` — empty ranges match everything.
#[inline]
fn u32_ranges_check(value: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.is_empty()
        || ranges
            .iter()
            .any(|&(start, end)| value >= start && value <= end)
}

/// Match a domain against a regex pattern using the `regex` crate.
/// mihomo compat: uses case-insensitive matching (regexp2.IgnoreCase).
fn match_domain_regex(pattern: &str, domain: &str) -> bool {
    // Add (?i) for case-insensitive matching if not already present
    let pat = if pattern.starts_with("(?i)") {
        pattern.to_string()
    } else {
        format!("(?i){pattern}")
    };
    if let Ok(re) = Regex::new(&pat) {
        re.is_match(domain)
    } else {
        false
    }
}

/// Fallback CIDR check for rules without a pre-parsed index (logic sub-rules).
/// Malformed CIDRs (and family mismatches) never match.
fn check_ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    PreParsedCidr::parse(cidr).is_some_and(|c| c.matches(ip))
}

/// `d` is a strict subdomain of `s` — it ends with `.{s}`.
///
/// mihomo compat: the label-boundary check in `trie/domain.go` / DomainSuffix —
/// "oexample.com" must not match the suffix "example.com".
fn is_subdomain_of(d: &str, s: &str) -> bool {
    d.len() > s.len() && d.ends_with(s) && d.as_bytes()[d.len() - s.len() - 1] == b'.'
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (plen, tlen) = (pattern.len(), text.len());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < tlen {
        if pi < plen && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < plen && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < plen && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == plen
}

/// Fallback IP-SUFFIX check for rules without a pre-parsed index (logic
/// sub-rules).
fn check_ip_suffix(ip: &IpAddr, suffix: &str) -> bool {
    PreParsedSuffix::parse(suffix).is_some_and(|s| s.matches(ip))
}

fn default_home_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CLASH_HOME_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".config").join("mihomo")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_rule_domain() {
        let parsed = parse_rule("DOMAIN,example.com,Proxy").unwrap();
        assert_eq!(parsed.rule_type, "DOMAIN");
        assert_eq!(parsed.payload, "example.com");
        assert_eq!(parsed.target, "Proxy");
        assert!(parsed.params.is_empty());
    }

    #[test]
    fn parse_rule_domain_suffix() {
        let parsed = parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
        assert_eq!(parsed.rule_type, "DOMAIN-SUFFIX");
        assert_eq!(parsed.payload, "google.com");
        assert_eq!(parsed.target, "Proxy");
    }

    #[test]
    fn parse_rule_ip_cidr_with_params() {
        let parsed = parse_rule("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve").unwrap();
        assert_eq!(parsed.rule_type, "IP-CIDR");
        assert_eq!(parsed.payload, "192.168.0.0/16");
        assert_eq!(parsed.target, "DIRECT");
        assert_eq!(parsed.params, vec!["no-resolve"]);
    }

    #[test]
    fn parse_rule_match() {
        let parsed = parse_rule("MATCH,Proxy").unwrap();
        assert_eq!(parsed.rule_type, "MATCH");
        assert_eq!(parsed.payload, "");
        assert_eq!(parsed.target, "Proxy");
    }

    #[test]
    fn parse_rule_invalid_format() {
        let result = parse_rule("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn target_to_action_direct() {
        assert_eq!(target_to_action("DIRECT"), Action::Direct);
    }

    #[test]
    fn target_to_action_reject() {
        assert_eq!(target_to_action("REJECT"), Action::Reject);
    }

    #[test]
    fn target_to_action_reject_drop() {
        assert_eq!(target_to_action("REJECT-DROP"), Action::RejectDrop);
    }

    #[test]
    fn target_to_action_proxy_name() {
        assert_eq!(
            target_to_action("MyProxy"),
            Action::Proxy("MyProxy".to_string())
        );
    }

    #[tokio::test]
    async fn rule_engine_match_domain_rules() {
        let rules: Vec<RuleString> = vec![
            "DOMAIN,exact.example.com,Proxy".to_string(),
            "DOMAIN-SUFFIX,google.com,Proxy".to_string(),
            "DOMAIN-KEYWORD,facebook,Proxy".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        let providers = HashMap::new();
        let engine = RuleEngine::new(&rules, &providers).await.unwrap();

        // Exact domain match
        let meta = RuleMetadata {
            domain: Some("exact.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(
            engine.match_rules(&meta),
            Action::Proxy("Proxy".to_string())
        );

        // Suffix match
        let meta = RuleMetadata {
            domain: Some("www.google.com".to_string()),
            ..Default::default()
        };
        assert_eq!(
            engine.match_rules(&meta),
            Action::Proxy("Proxy".to_string())
        );

        // Keyword match
        let meta = RuleMetadata {
            domain: Some("m.facebook.com".to_string()),
            ..Default::default()
        };
        assert_eq!(
            engine.match_rules(&meta),
            Action::Proxy("Proxy".to_string())
        );

        // No domain match -> falls through to MATCH rule
        let meta = RuleMetadata {
            domain: Some("random.xyz".to_string()),
            ..Default::default()
        };
        assert_eq!(engine.match_rules(&meta), Action::Direct);
    }

    #[test]
    fn ip_is_lan_classification() {
        use std::net::Ipv4Addr;
        assert!(ip_is_lan(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(ip_is_lan(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(ip_is_lan(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(ip_is_lan(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(ip_is_lan(&IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        assert!(!ip_is_lan(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!ip_is_lan(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[tokio::test]
    async fn rule_engine_geoip_lan() {
        use std::net::Ipv4Addr;
        // mihomo compat: GEOIP,lan matches private/reserved IPs with no mmdb.
        let rules: Vec<RuleString> =
            vec!["GEOIP,lan,DIRECT".to_string(), "MATCH,Proxy".to_string()];
        let providers = HashMap::new();
        let engine = RuleEngine::new(&rules, &providers).await.unwrap();

        let lan = RuleMetadata {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            ..Default::default()
        };
        assert_eq!(engine.match_rules(&lan), Action::Direct);

        let public = RuleMetadata {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            ..Default::default()
        };
        assert_eq!(
            engine.match_rules(&public),
            Action::Proxy("Proxy".to_string())
        );
    }

    #[tokio::test]
    async fn rule_engine_match_ip_rules() {
        let rules: Vec<RuleString> = vec![
            "IP-CIDR,192.168.0.0/16,DIRECT".to_string(),
            "IP-CIDR6,2001:db8::/32,DIRECT".to_string(),
            "MATCH,Proxy".to_string(),
        ];
        let providers = HashMap::new();
        let engine = RuleEngine::new(&rules, &providers).await.unwrap();

        // IPv4 CIDR match
        let meta = RuleMetadata {
            dst_ip: Some("192.168.1.100".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(engine.match_rules(&meta), Action::Direct);

        // IPv6 CIDR match
        let meta = RuleMetadata {
            dst_ip: Some("2001:db8::1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(engine.match_rules(&meta), Action::Direct);

        // No IP match -> MATCH
        let meta = RuleMetadata {
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(
            engine.match_rules(&meta),
            Action::Proxy("Proxy".to_string())
        );
    }

    // mihomo compat: tunnel.go match() resolves the host on demand when an
    // IP-based rule is reached with an empty DstIP. These cover the
    // needs_ip_resolution() guard that drives that resolution in conn/mod.rs.

    #[tokio::test]
    async fn needs_ip_resolution_true_when_ip_rule_reached_without_dst_ip() {
        let rules: Vec<RuleString> = vec![
            "DOMAIN-SUFFIX,google.com,Proxy".to_string(),
            "IP-CIDR,1.2.3.0/24,DIRECT".to_string(),
            "MATCH,Proxy".to_string(),
        ];
        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        // Domain that no DOMAIN rule matches and no dst_ip (FakeIP cleared):
        // evaluation reaches the IP-CIDR rule, so resolution is required.
        let meta = RuleMetadata {
            domain: Some("random.xyz".to_string()),
            dst_ip: None,
            ..Default::default()
        };
        assert!(engine.needs_ip_resolution(&meta));
    }

    #[tokio::test]
    async fn needs_ip_resolution_false_when_domain_rule_matches_first() {
        let rules: Vec<RuleString> = vec![
            "DOMAIN-SUFFIX,google.com,Proxy".to_string(),
            "IP-CIDR,1.2.3.0/24,DIRECT".to_string(),
            "MATCH,Proxy".to_string(),
        ];
        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        // A domain rule matches before the IP-CIDR rule is ever reached.
        let meta = RuleMetadata {
            domain: Some("www.google.com".to_string()),
            dst_ip: None,
            ..Default::default()
        };
        assert!(!engine.needs_ip_resolution(&meta));
    }

    #[tokio::test]
    async fn needs_ip_resolution_false_for_no_resolve_ip_rule() {
        let rules: Vec<RuleString> = vec![
            "IP-CIDR,1.2.3.0/24,DIRECT,no-resolve".to_string(),
            "MATCH,Proxy".to_string(),
        ];
        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        // no-resolve IP rules never trigger on-demand resolution.
        let meta = RuleMetadata {
            domain: Some("random.xyz".to_string()),
            dst_ip: None,
            ..Default::default()
        };
        assert!(!engine.needs_ip_resolution(&meta));
    }

    #[tokio::test]
    async fn needs_ip_resolution_false_without_any_ip_rule() {
        let rules: Vec<RuleString> = vec![
            "DOMAIN-SUFFIX,google.com,Proxy".to_string(),
            "MATCH,Proxy".to_string(),
        ];
        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        let meta = RuleMetadata {
            domain: Some("random.xyz".to_string()),
            dst_ip: None,
            ..Default::default()
        };
        assert!(!engine.needs_ip_resolution(&meta));
    }

    #[tokio::test]
    async fn resolve_on_demand_flips_ip_rule_from_proxy_to_direct() {
        // Regression for the domestic-routing leak: without a resolved dst_ip,
        // an IP rule cannot match and the connection falls through to the proxy
        // catch-all. Once the host is resolved to a real (domestic) IP, the IP
        // rule matches and routes DIRECT.
        let rules: Vec<RuleString> = vec![
            "IP-CIDR,1.2.3.0/24,DIRECT".to_string(),
            "MATCH,Proxy".to_string(),
        ];
        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        // Before resolution: dst_ip is None → leaks to the proxy catch-all.
        let mut meta = RuleMetadata {
            domain: Some("domestic.example".to_string()),
            dst_ip: None,
            ..Default::default()
        };
        assert!(engine.needs_ip_resolution(&meta));
        assert_eq!(
            engine.match_rules(&meta),
            Action::Proxy("Proxy".to_string())
        );

        // After resolution (conn/mod.rs sets dst_ip): the IP rule matches DIRECT.
        meta.dst_ip = Some("1.2.3.4".parse().unwrap());
        assert_eq!(engine.match_rules(&meta), Action::Direct);
    }

    #[tokio::test]
    async fn rule_engine_default_match_rule() {
        let rules: Vec<RuleString> = vec!["MATCH,REJECT".to_string()];
        let providers = HashMap::new();
        let engine = RuleEngine::new(&rules, &providers).await.unwrap();

        let meta = RuleMetadata::default();
        assert_eq!(engine.match_rules(&meta), Action::Reject);
    }

    #[tokio::test]
    async fn rule_engine_no_match_defaults_to_direct() {
        // No MATCH rule at the end
        let rules: Vec<RuleString> = vec!["DOMAIN,example.com,Proxy".to_string()];
        let providers = HashMap::new();
        let engine = RuleEngine::new(&rules, &providers).await.unwrap();

        let meta = RuleMetadata {
            domain: Some("other.com".to_string()),
            ..Default::default()
        };
        assert_eq!(engine.match_rules(&meta), Action::Direct);
    }

    #[test]
    fn check_ip_in_cidr_ipv4() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(check_ip_in_cidr(&ip, "192.168.0.0/16"));
        assert!(check_ip_in_cidr(&ip, "192.168.1.0/24"));
        assert!(!check_ip_in_cidr(&ip, "10.0.0.0/8"));
    }

    #[test]
    fn check_ip_in_cidr_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(check_ip_in_cidr(&ip, "2001:db8::/32"));
        assert!(!check_ip_in_cidr(&ip, "fe80::/10"));
    }

    #[test]
    fn match_domain_regex_exact() {
        assert!(match_domain_regex("^example.com$", "example.com"));
        assert!(!match_domain_regex("^example.com$", "www.example.com"));
    }

    #[test]
    fn match_domain_regex_starts_with() {
        assert!(match_domain_regex("^www", "www.example.com"));
        assert!(!match_domain_regex("^www", "example.com"));
    }

    #[test]
    fn match_domain_regex_ends_with() {
        assert!(match_domain_regex(".com$", "example.com"));
        assert!(!match_domain_regex(".com$", "example.org"));
    }

    #[test]
    fn match_domain_regex_wildcard() {
        assert!(match_domain_regex("^www.*com$", "www.example.com"));
        assert!(match_domain_regex("goo.*le", "google.com"));
    }

    #[test]
    fn parse_logic_sub_rules_test() {
        // mihomo compat: logic.go format/findSubRuleRange — second-level
        // ranges of the wrapped payload become the sub-rules.
        let subs = parse_logic_sub_rules("((DOMAIN-SUFFIX,google.com),(NETWORK,udp))").unwrap();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].rule_type, "DOMAIN-SUFFIX");
        assert_eq!(subs[0].payload, "google.com");
        assert_eq!(subs[1].rule_type, "NETWORK");
        assert_eq!(subs[1].payload, "udp");
    }

    #[test]
    fn parse_logic_nested() {
        // Nested logic parses recursively through the full parser.
        let rule =
            parse_rule("AND,((OR,((DOMAIN,a.com),(DOMAIN,b.com))),(NETWORK,tcp)),Proxy").unwrap();
        assert_eq!(rule.rule_type, "AND");
        assert_eq!(rule.target, "Proxy");
        assert_eq!(rule.sub_rules.len(), 2);
        assert_eq!(rule.sub_rules[0].rule_type, "OR");
        assert_eq!(rule.sub_rules[0].sub_rules.len(), 2);
        assert_eq!(rule.sub_rules[1].rule_type, "NETWORK");
    }

    #[test]
    fn parse_logic_sub_rule_params() {
        // (IP-CIDR,1.2.3.0/24,no-resolve) inside logic keeps its params.
        let rule = parse_rule("AND,((IP-CIDR,1.2.3.0/24,no-resolve),(NETWORK,tcp)),Proxy").unwrap();
        assert_eq!(rule.sub_rules[0].payload, "1.2.3.0/24");
        assert_eq!(rule.sub_rules[0].params, vec!["no-resolve"]);
    }

    #[test]
    fn parse_domain_regex_with_commas() {
        // mihomo compat: base.go:55-61 — target is the LAST item; the payload
        // is the rejoined middle.
        let rule = parse_rule(r"DOMAIN-REGEX,^a{1,3}\.com$,Proxy").unwrap();
        assert_eq!(rule.payload, r"^a{1,3}\.com$");
        assert_eq!(rule.target, "Proxy");
    }

    #[test]
    fn parse_sub_rule_condition_and_group() {
        // mihomo compat: payload = gating condition, target = group name.
        let rule = parse_rule("SUB-RULE,(DOMAIN,example.com),my-group").unwrap();
        assert_eq!(rule.rule_type, "SUB-RULE");
        assert_eq!(rule.target, "my-group");
        assert_eq!(rule.sub_rules.len(), 1);
        assert_eq!(rule.sub_rules[0].rule_type, "DOMAIN");
        assert_eq!(rule.sub_rules[0].payload, "example.com");
    }

    #[tokio::test]
    async fn sub_rules_regexes_are_compiled_and_match() {
        // Regression: rules added via set_sub_rules must go through the same
        // regex pre-compilation as the main list — PROCESS-*-REGEX has no
        // fallback and would silently never match otherwise.
        let rules: Vec<RuleString> = vec![
            "SUB-RULE,(NETWORK,tcp),grp".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        let mut engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        let mut sub_rules = HashMap::new();
        sub_rules.insert(
            "grp".to_string(),
            vec![
                r"PROCESS-NAME-REGEX,^curl$,REJECT".to_string(),
                r"DOMAIN-REGEX,^ex\d+\.com$,Proxy".to_string(),
            ],
        );
        engine.set_sub_rules(&sub_rules);

        // The regex is compiled into the rule itself at parse time.
        let grp = engine.sub_rules.get("grp").expect("group loaded");
        assert!(grp.iter().all(|r| matches!(r.prepared, Prepared::Regex(_))));

        // DOMAIN-REGEX in the sub-rule group matches.
        let meta = RuleMetadata {
            domain: Some("ex42.com".to_string()),
            network: "tcp",
            ..Default::default()
        };
        assert_eq!(
            engine.match_rules(&meta),
            Action::Proxy("Proxy".to_string())
        );

        // PROCESS-NAME-REGEX matches too (case-insensitive, mihomo IgnoreCase).
        let meta = RuleMetadata {
            process_name: Some("CURL".to_string()),
            network: "tcp",
            ..Default::default()
        };
        assert_eq!(engine.match_rules(&meta), Action::Reject);
    }

    // -----------------------------------------------------------------------
    // Port range matching tests (mihomo compat)
    // -----------------------------------------------------------------------

    #[test]
    fn port_matches_single() {
        assert!(port_matches(80, "80"));
        assert!(!port_matches(81, "80"));
    }

    #[test]
    fn port_matches_multi_slash() {
        assert!(port_matches(80, "80/443/8080"));
        assert!(port_matches(443, "80/443/8080"));
        assert!(port_matches(8080, "80/443/8080"));
        assert!(!port_matches(81, "80/443/8080"));
    }

    #[test]
    fn port_matches_range() {
        assert!(port_matches(1000, "1000-2000"));
        assert!(port_matches(1500, "1000-2000"));
        assert!(port_matches(2000, "1000-2000"));
        assert!(!port_matches(999, "1000-2000"));
        assert!(!port_matches(2001, "1000-2000"));
    }

    #[test]
    fn port_matches_combined() {
        // "80-90/443/8080-9090"
        assert!(port_matches(80, "80-90/443/8080-9090"));
        assert!(port_matches(85, "80-90/443/8080-9090"));
        assert!(port_matches(90, "80-90/443/8080-9090"));
        assert!(port_matches(443, "80-90/443/8080-9090"));
        assert!(port_matches(8080, "80-90/443/8080-9090"));
        assert!(port_matches(9000, "80-90/443/8080-9090"));
        assert!(port_matches(9090, "80-90/443/8080-9090"));
        assert!(!port_matches(91, "80-90/443/8080-9090"));
        assert!(!port_matches(444, "80-90/443/8080-9090"));
        assert!(!port_matches(8079, "80-90/443/8080-9090"));
    }

    #[test]
    fn port_matches_comma_separator() {
        // mihomo compat: commas treated as slashes
        assert!(port_matches(80, "80,443"));
        assert!(port_matches(443, "80,443"));
        assert!(!port_matches(81, "80,443"));
    }

    #[test]
    fn port_matches_empty_matches_all() {
        // mihomo compat: empty/wildcard ranges match everything
        assert!(port_matches(80, ""));
        assert!(port_matches(443, ""));
    }

    #[test]
    fn parse_port_ranges_rejects_invalid_parts() {
        // mihomo compat: port.go NewPort errors on unparseable specs (config
        // load failure), no silent skipping.
        assert!(parse_port_ranges("80/abc/443").is_err());
        assert!(parse_rule("DST-PORT,abc,Proxy").is_err());
        assert!(parse_rule("DST-PORT,*,Proxy").is_err());
        // Inverted ranges are swapped (range.go NewRange).
        assert_eq!(parse_port_ranges("2000-1000").unwrap(), vec![(1000, 2000)]);
    }

    #[test]
    fn ip_suffix_matches_trailing_bits() {
        // mihomo compat: ipsuffix.go — IP-SUFFIX,8.8.8.8/24 matches x.8.8.8.
        let ip: IpAddr = "1.8.8.8".parse().unwrap();
        assert!(check_ip_suffix(&ip, "8.8.8.8/24"));
        let ip: IpAddr = "8.8.8.1".parse().unwrap();
        assert!(!check_ip_suffix(&ip, "8.8.8.8/24"));
        // Partial byte: trailing 17 bits — low bit of the boundary byte counts.
        let ip: IpAddr = "1.0.8.8".parse().unwrap();
        assert!(check_ip_suffix(&ip, "8.8.8.8/17"));
        // Family mismatch never matches.
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(!check_ip_suffix(&ip, "8.8.8.8/24"));
    }

    #[test]
    fn uid_ranges_and_lists() {
        assert_eq!(
            parse_u32_ranges("1000-1100/2000").unwrap(),
            vec![(1000, 1100), (2000, 2000)]
        );
        assert!(parse_rule("UID,abc,Proxy").is_err());
        assert!(parse_rule("DSCP,100,Proxy").is_err()); // > 63
    }

    // -----------------------------------------------------------------------
    // Domain regex with real regex crate tests
    // -----------------------------------------------------------------------

    #[test]
    fn match_domain_regex_character_class() {
        // Real regex features that the old basic matcher couldn't handle
        assert!(match_domain_regex(
            r"^(www|api)\.example\.com$",
            "www.example.com"
        ));
        assert!(match_domain_regex(
            r"^(www|api)\.example\.com$",
            "api.example.com"
        ));
        assert!(!match_domain_regex(
            r"^(www|api)\.example\.com$",
            "cdn.example.com"
        ));
    }

    #[test]
    fn match_domain_regex_dot_matches_any() {
        // In real regex, '.' matches any character
        assert!(match_domain_regex("example.com", "exampleXcom"));
    }

    #[test]
    fn match_domain_regex_invalid_pattern_returns_false() {
        // Invalid regex should not panic, just return false
        assert!(!match_domain_regex("[invalid", "example.com"));
    }

    /// Backs the `/providers/rules` REST API. We rely on the engine
    /// capturing real ruleCount + updatedAt at construction time so the
    /// dashboard sees genuine numbers, not zeros and empty strings.
    #[tokio::test]
    async fn provider_info_captures_rule_count_and_timestamp() {
        // Create a file provider on disk with three domain entries so the
        // engine can `load()` real rules and surface a real count.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rules.txt");
        std::fs::write(&file, "example.com\ngoogle.com\nyoutube.com\n").unwrap();

        let mut providers = HashMap::new();
        providers.insert(
            "domestic".to_string(),
            RuleProviderConfig {
                provider_type: "file".to_string(),
                behavior: Some("domain".to_string()),
                url: None,
                path: Some(file.to_string_lossy().to_string()),
                interval: None,
                format: Some("text".to_string()),
                extra: HashMap::new(),
            },
        );
        let rules = vec!["RULE-SET,domestic,DIRECT".to_string()];
        let before_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let engine = RuleEngine::new(&rules, &providers).await.unwrap();
        let info = engine.provider_info();

        let pi = info.get("domestic").expect("provider info must be present");
        assert_eq!(pi.name, "domestic");
        assert_eq!(pi.vehicle_type, "File");
        assert_eq!(pi.behavior, "domain");
        assert_eq!(pi.format, "text");
        assert_eq!(pi.rule_count, 3, "must reflect real rule count, not 0");
        assert!(
            pi.updated_at_unix >= before_unix,
            "updated_at must be set to load time, not 0"
        );
    }

    // ---------------------------------------------------------------------
    // Golden matcher corpus
    //
    // One rule per matcher kind, each with a unique target, so a case's
    // expected target names exactly which arm fired. This pins the observable
    // contract of `match_rules_detailed` — (Action, rule_type, payload) — and
    // must stay byte-identical across any dispatch refactor.
    //
    // Rule order is load-bearing (first match wins, mihomo tunnel.go match()),
    // so payloads are chosen to be mutually disjoint: no case can reach its
    // intended rule by accident or be shadowed by an earlier one.
    // ---------------------------------------------------------------------

    fn golden_rules() -> Vec<RuleString> {
        [
            // Domain family.
            "DOMAIN,exact.golden.test,R-domain",
            "DOMAIN-SUFFIX,suffix.golden.test,R-domain-suffix",
            "DOMAIN-SUFFIX-STRICT,strict.golden.test,R-domain-suffix-strict",
            "DOMAIN-STAR,star.golden.test,R-domain-star",
            "DOMAIN-KEYWORD,kwgolden,R-domain-keyword",
            "DOMAIN-WILDCARD,wild?.golden.test,R-domain-wildcard",
            r"DOMAIN-REGEX,^re[0-9]+\.golden\.test$,R-domain-regex",
            // No geosite db in unit tests, so this arm is exercised as a
            // non-match (it must not panic or match everything).
            "GEOSITE,cn,R-geosite",
            // Process family.
            "PROCESS-NAME,goldencurl,R-process-name",
            "PROCESS-PATH,/usr/bin/goldenwget,R-process-path",
            "PROCESS-NAME-REGEX,^goldenre[0-9]+$,R-process-name-regex",
            "PROCESS-PATH-REGEX,^/opt/goldenre[0-9]+$,R-process-path-regex",
            "PROCESS-NAME-WILDCARD,goldenwc*,R-process-name-wildcard",
            "PROCESS-PATH-WILDCARD,/opt/goldenwc*,R-process-path-wildcard",
            // Port family.
            "DST-PORT,10001-10005,R-dst-port",
            "SRC-PORT,20001,R-src-port",
            "IN-PORT,30001,R-in-port",
            // Inbound family.
            "IN-TYPE,socks,R-in-type",
            "IN-USER,goldenuser,R-in-user",
            "IN-NAME,goldenname,R-in-name",
            // Misc.
            "NETWORK,udp,R-network",
            "UID,4242,R-uid",
            "DSCP,42,R-dscp",
            // IP family. Source rules come first so a private src_ip in a
            // later SRC-GEOIP case can't shadow them.
            "SRC-IP-CIDR,10.77.0.0/16,R-src-ip-cidr",
            "SRC-IP-SUFFIX,0.0.0.88/8,R-src-ip-suffix",
            // No ASN db in unit tests — exercised as a non-match.
            "SRC-IP-ASN,64512,R-src-ip-asn",
            "IP-CIDR,203.0.113.0/24,R-ip-cidr,no-resolve",
            "IP-CIDR6,2001:db8::/32,R-ip-cidr6,no-resolve",
            "IP-SUFFIX,0.0.0.99/8,R-ip-suffix,no-resolve",
            "IP-ASN,64513,R-ip-asn,no-resolve",
            "GEOIP,lan,R-geoip-lan,no-resolve",
            "SRC-GEOIP,lan,R-src-geoip-lan",
            // Logic family.
            "AND,((DOMAIN,and.golden.test),(DST-PORT,10443)),R-and",
            "OR,((DOMAIN,or1.golden.test),(DOMAIN,or2.golden.test)),R-or",
            // Deliberately narrow: matches only domains WITHOUT "golden", so
            // it cannot swallow the SUB-RULE and MATCH cases below.
            "NOT,((DOMAIN-KEYWORD,golden)),R-not",
            "SUB-RULE,(DOMAIN,sub.golden.test),golden-group",
            "MATCH,DIRECT",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    async fn golden_engine() -> RuleEngine {
        let mut engine = RuleEngine::new(&golden_rules(), &HashMap::new())
            .await
            .unwrap();
        let mut groups = HashMap::new();
        groups.insert(
            "golden-group".to_string(),
            vec![
                "DOMAIN,never.golden.test,R-subrule-first".to_string(),
                "MATCH,R-subrule".to_string(),
            ],
        );
        engine.set_sub_rules(&groups);
        engine
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn golden_matcher_corpus() {
        let engine = golden_engine().await;

        // (case label, metadata, expected target, expected rule_type, expected payload)
        let cases: Vec<(&str, RuleMetadata, &str, &str, &str)> = vec![
            (
                "domain exact",
                RuleMetadata {
                    domain: Some("exact.golden.test".into()),
                    ..Default::default()
                },
                "R-domain",
                "DOMAIN",
                "exact.golden.test",
            ),
            (
                "domain suffix, subdomain",
                RuleMetadata {
                    domain: Some("www.suffix.golden.test".into()),
                    ..Default::default()
                },
                "R-domain-suffix",
                "DOMAIN-SUFFIX",
                "suffix.golden.test",
            ),
            (
                "domain suffix, bare domain also matches",
                RuleMetadata {
                    domain: Some("suffix.golden.test".into()),
                    ..Default::default()
                },
                "R-domain-suffix",
                "DOMAIN-SUFFIX",
                "suffix.golden.test",
            ),
            (
                "domain suffix strict, subdomain only",
                RuleMetadata {
                    domain: Some("a.strict.golden.test".into()),
                    ..Default::default()
                },
                "R-domain-suffix-strict",
                "DOMAIN-SUFFIX-STRICT",
                "strict.golden.test",
            ),
            (
                "domain star, exactly one extra label",
                RuleMetadata {
                    domain: Some("one.star.golden.test".into()),
                    ..Default::default()
                },
                "R-domain-star",
                "DOMAIN-STAR",
                "star.golden.test",
            ),
            (
                "domain keyword",
                RuleMetadata {
                    domain: Some("host.kwgolden.example".into()),
                    ..Default::default()
                },
                "R-domain-keyword",
                "DOMAIN-KEYWORD",
                "kwgolden",
            ),
            (
                "domain wildcard, ? is one char",
                RuleMetadata {
                    domain: Some("wildx.golden.test".into()),
                    ..Default::default()
                },
                "R-domain-wildcard",
                "DOMAIN-WILDCARD",
                "wild?.golden.test",
            ),
            (
                "domain regex",
                RuleMetadata {
                    domain: Some("re42.golden.test".into()),
                    ..Default::default()
                },
                "R-domain-regex",
                "DOMAIN-REGEX",
                r"^re[0-9]+\.golden\.test$",
            ),
            (
                "process name, case-insensitive",
                RuleMetadata {
                    process_name: Some("GoldenCurl".into()),
                    ..Default::default()
                },
                "R-process-name",
                "PROCESS-NAME",
                "goldencurl",
            ),
            (
                "process path",
                RuleMetadata {
                    process_path: Some("/usr/bin/goldenwget".into()),
                    ..Default::default()
                },
                "R-process-path",
                "PROCESS-PATH",
                "/usr/bin/goldenwget",
            ),
            (
                "process name regex",
                RuleMetadata {
                    process_name: Some("goldenre7".into()),
                    ..Default::default()
                },
                "R-process-name-regex",
                "PROCESS-NAME-REGEX",
                "^goldenre[0-9]+$",
            ),
            (
                "process path regex",
                RuleMetadata {
                    process_path: Some("/opt/goldenre7".into()),
                    ..Default::default()
                },
                "R-process-path-regex",
                "PROCESS-PATH-REGEX",
                "^/opt/goldenre[0-9]+$",
            ),
            (
                "process name wildcard",
                RuleMetadata {
                    process_name: Some("goldenwcanything".into()),
                    ..Default::default()
                },
                "R-process-name-wildcard",
                "PROCESS-NAME-WILDCARD",
                "goldenwc*",
            ),
            (
                "process path wildcard",
                RuleMetadata {
                    process_path: Some("/opt/goldenwc/bin".into()),
                    ..Default::default()
                },
                "R-process-path-wildcard",
                "PROCESS-PATH-WILDCARD",
                "/opt/goldenwc*",
            ),
            (
                "dst port range",
                RuleMetadata {
                    dst_port: 10003,
                    ..Default::default()
                },
                "R-dst-port",
                "DST-PORT",
                "10001-10005",
            ),
            (
                "src port",
                RuleMetadata {
                    src_port: 20001,
                    ..Default::default()
                },
                "R-src-port",
                "SRC-PORT",
                "20001",
            ),
            (
                "in port",
                RuleMetadata {
                    in_port: Some(30001),
                    ..Default::default()
                },
                "R-in-port",
                "IN-PORT",
                "30001",
            ),
            (
                "in type, SOCKS expands to socks5",
                RuleMetadata {
                    in_type: Some("socks5"),
                    ..Default::default()
                },
                "R-in-type",
                "IN-TYPE",
                "socks",
            ),
            (
                "in user",
                RuleMetadata {
                    in_user: Some("goldenuser".into()),
                    ..Default::default()
                },
                "R-in-user",
                "IN-USER",
                "goldenuser",
            ),
            (
                "in name",
                RuleMetadata {
                    in_name: Some("goldenname".into()),
                    ..Default::default()
                },
                "R-in-name",
                "IN-NAME",
                "goldenname",
            ),
            (
                "network udp",
                RuleMetadata {
                    network: "udp",
                    ..Default::default()
                },
                "R-network",
                "NETWORK",
                "udp",
            ),
            (
                "uid",
                RuleMetadata {
                    uid: Some(4242),
                    ..Default::default()
                },
                "R-uid",
                "UID",
                "4242",
            ),
            (
                "dscp",
                RuleMetadata {
                    dscp: Some(42),
                    ..Default::default()
                },
                "R-dscp",
                "DSCP",
                "42",
            ),
            (
                "src ip cidr",
                RuleMetadata {
                    src_ip: Some(ip("10.77.1.2")),
                    ..Default::default()
                },
                "R-src-ip-cidr",
                "SRC-IP-CIDR",
                "10.77.0.0/16",
            ),
            (
                "src ip suffix, trailing octet",
                RuleMetadata {
                    src_ip: Some(ip("172.16.5.88")),
                    ..Default::default()
                },
                "R-src-ip-suffix",
                "SRC-IP-SUFFIX",
                "0.0.0.88/8",
            ),
            (
                "ip cidr v4",
                RuleMetadata {
                    dst_ip: Some(ip("203.0.113.7")),
                    ..Default::default()
                },
                "R-ip-cidr",
                "IP-CIDR",
                "203.0.113.0/24",
            ),
            (
                "ip cidr v6",
                RuleMetadata {
                    dst_ip: Some(ip("2001:db8::1")),
                    ..Default::default()
                },
                "R-ip-cidr6",
                "IP-CIDR6",
                "2001:db8::/32",
            ),
            (
                "ip suffix, trailing octet",
                RuleMetadata {
                    dst_ip: Some(ip("198.51.100.99")),
                    ..Default::default()
                },
                "R-ip-suffix",
                "IP-SUFFIX",
                "0.0.0.99/8",
            ),
            (
                "geoip lan pseudo-country needs no mmdb",
                RuleMetadata {
                    dst_ip: Some(ip("10.0.0.5")),
                    ..Default::default()
                },
                "R-geoip-lan",
                "GEOIP",
                "lan",
            ),
            (
                "src-geoip lan",
                RuleMetadata {
                    src_ip: Some(ip("192.168.9.9")),
                    ..Default::default()
                },
                "R-src-geoip-lan",
                "SRC-GEOIP",
                "lan",
            ),
            (
                "AND, both conditions",
                RuleMetadata {
                    domain: Some("and.golden.test".into()),
                    dst_port: 10443,
                    ..Default::default()
                },
                "R-and",
                "AND",
                "((DOMAIN,and.golden.test),(DST-PORT,10443))",
            ),
            (
                "OR, second branch",
                RuleMetadata {
                    domain: Some("or2.golden.test".into()),
                    ..Default::default()
                },
                "R-or",
                "OR",
                "((DOMAIN,or1.golden.test),(DOMAIN,or2.golden.test))",
            ),
            (
                "NOT, inner condition false",
                RuleMetadata {
                    domain: Some("plain.example.org".into()),
                    ..Default::default()
                },
                "R-not",
                "NOT",
                "((DOMAIN-KEYWORD,golden))",
            ),
            (
                "SUB-RULE, gate matches then group is walked",
                RuleMetadata {
                    domain: Some("sub.golden.test".into()),
                    ..Default::default()
                },
                "R-subrule",
                "SUB-RULE",
                "(DOMAIN,sub.golden.test)",
            ),
            (
                "no rule matches an unmatched golden domain -> MATCH",
                RuleMetadata {
                    domain: Some("fallthrough.golden.test".into()),
                    ..Default::default()
                },
                "DIRECT",
                "MATCH",
                "",
            ),
        ];

        for (label, meta, want_target, want_type, want_payload) in cases {
            let (action, rule_type, payload) = engine.match_rules_detailed(&meta);
            let want_action = if want_target == "DIRECT" {
                Action::Direct
            } else {
                Action::Proxy(want_target.to_string())
            };
            assert_eq!(action, want_action, "action for case '{label}'");
            assert_eq!(rule_type, want_type, "rule_type for case '{label}'");
            assert_eq!(payload, want_payload, "payload for case '{label}'");
        }
    }

    /// The AND/OR/NOT arms must NOT match when their conditions fail; without
    /// this the golden table above could pass on a matcher that says yes to
    /// everything.
    #[tokio::test]
    async fn golden_logic_rules_reject_non_matches() {
        let engine = golden_engine().await;

        // AND with only the domain half satisfied (port is wrong) must fall
        // through past R-and.
        let (action, rule_type, _) = engine.match_rules_detailed(&RuleMetadata {
            domain: Some("and.golden.test".into()),
            dst_port: 9999,
            ..Default::default()
        });
        assert_ne!(
            rule_type, "AND",
            "AND must not match on a partial condition"
        );
        assert_eq!(action, Action::Direct, "should fall through to MATCH");

        // NOT must not fire when its inner condition holds.
        let (_, rule_type, _) = engine.match_rules_detailed(&RuleMetadata {
            domain: Some("unmatched.golden.test".into()),
            ..Default::default()
        });
        assert_ne!(rule_type, "NOT");

        // A SUB-RULE gate that fails must not consult the group at all.
        let (_, rule_type, _) = engine.match_rules_detailed(&RuleMetadata {
            domain: Some("notsub.golden.test".into()),
            ..Default::default()
        });
        assert_ne!(rule_type, "SUB-RULE");
    }

    /// Nested logic rules must use the same pre-parsed matchers as top-level
    /// ones. Before the `Prepared` refactor, nested rules recursed with
    /// `rule_idx = usize::MAX`, missing every side table and re-parsing the
    /// CIDR / port / range payload string on each match.
    #[tokio::test]
    async fn nested_logic_rules_match_ip_and_port_children() {
        let rules: Vec<RuleString> = vec![
            "AND,((IP-CIDR,198.18.0.0/16),(DST-PORT,8080-8090)),NestedProxy".to_string(),
            "OR,((IP-SUFFIX,0.0.0.77/8),(UID,7777)),NestedOr".to_string(),
            "NOT,((IP-CIDR,10.0.0.0/8)),NestedNot".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();

        // Nested IP-CIDR + DST-PORT.
        assert_eq!(
            engine.match_rules(&RuleMetadata {
                dst_ip: Some(ip("198.18.1.1")),
                dst_port: 8085,
                ..Default::default()
            }),
            Action::Proxy("NestedProxy".into())
        );
        // Right IP, wrong port -> AND fails.
        assert_ne!(
            engine.match_rules(&RuleMetadata {
                dst_ip: Some(ip("198.18.1.1")),
                dst_port: 9999,
                ..Default::default()
            }),
            Action::Proxy("NestedProxy".into())
        );
        // Nested IP-SUFFIX branch of the OR.
        assert_eq!(
            engine.match_rules(&RuleMetadata {
                dst_ip: Some(ip("203.0.113.77")),
                ..Default::default()
            }),
            Action::Proxy("NestedOr".into())
        );
        // Nested UID branch of the OR.
        assert_eq!(
            engine.match_rules(&RuleMetadata {
                dst_ip: Some(ip("8.8.8.8")),
                uid: Some(7777),
                ..Default::default()
            }),
            Action::Proxy("NestedOr".into())
        );
        // Nested NOT: 10.x is inside the inner CIDR, so NOT must not fire and
        // we fall through to MATCH.
        assert_eq!(
            engine.match_rules(&RuleMetadata {
                dst_ip: Some(ip("10.1.2.3")),
                ..Default::default()
            }),
            Action::Direct
        );
    }

    /// Timing harness for the linear rule walk. Not a correctness test — run
    /// it explicitly to get a number:
    ///   cargo test --release -- --ignored --nocapture rule_match_timing
    #[tokio::test]
    #[ignore]
    async fn rule_match_timing() {
        // A corpus shaped like openwrt/openclash/nx.yaml: mostly domain rules,
        // a large IP-CIDR tail, and GEOIP + MATCH at the end.
        let mut rules: Vec<RuleString> = Vec::with_capacity(7000);
        for i in 0..4000 {
            rules.push(format!("DOMAIN-SUFFIX,d{i}.example.com,P"));
        }
        for i in 0..1500 {
            rules.push(format!(
                "IP-CIDR,10.{}.{}.0/24,P,no-resolve",
                i / 256,
                i % 256
            ));
        }
        for i in 0..500 {
            rules.push(format!("DOMAIN-KEYWORD,kw{i},P"));
        }
        for i in 0..500 {
            rules.push(format!("DST-PORT,{}-{},P", 20000 + i * 2, 20001 + i * 2));
        }
        for i in 0..500 {
            rules.push(format!("IP-SUFFIX,0.0.{}.0/16,P,no-resolve", i % 256));
        }
        rules.push("GEOIP,CN,DIRECT,no-resolve".to_string());
        rules.push("MATCH,P".to_string());

        let engine = RuleEngine::new(&rules, &HashMap::new()).await.unwrap();
        println!("rules: {}", engine.rule_count());

        // Worst case: nothing matches until the very end, so every rule runs.
        let meta = RuleMetadata {
            domain: Some("no-such-domain.invalid".to_string()),
            dst_ip: Some(ip("198.51.100.1")),
            dst_port: 443,
            network: "tcp",
            ..Default::default()
        };

        // Warm up so we time steady state, not first-touch page faults.
        for _ in 0..100 {
            std::hint::black_box(engine.match_rules(&meta));
        }

        const N: u32 = 2000;
        let start = std::time::Instant::now();
        for _ in 0..N {
            std::hint::black_box(engine.match_rules(&meta));
        }
        let elapsed = start.elapsed();
        println!(
            "full-walk match: {N} iters in {elapsed:?} => {:?}/match",
            elapsed / N
        );
    }
}
