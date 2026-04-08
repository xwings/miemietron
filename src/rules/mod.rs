pub mod domain;
pub mod geoip;
pub mod geosite;
pub mod ipcidr;
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
    pub network: String, // "tcp" or "udp"
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub in_port: Option<u16>,
    pub in_type: Option<String>,
    pub in_user: Option<String>,
    pub in_name: Option<String>,
    pub uid: Option<u32>,
    pub dscp: Option<u8>,
}

/// Parsed rule entry.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub rule_type: String,
    pub payload: String,
    pub target: String,
    pub params: Vec<String>,
}

pub struct RuleEngine {
    rules: Vec<ParsedRule>,
    rule_stats: Vec<RuleStats>,
    geoip_matcher: geoip::GeoIpMatcher,
    geosite_matcher: geosite::GeoSiteMatcher,
    sub_rules: HashMap<String, Vec<ParsedRule>>,
}

impl RuleEngine {
    pub async fn new(
        rule_strings: &[RuleString],
        _providers: &HashMap<String, RuleProviderConfig>,
    ) -> Result<Self> {
        // Use default home directory when none is provided
        let home_dir = default_home_dir();
        Self::with_home_dir(rule_strings, _providers, &home_dir).await
    }

    /// Create a new RuleEngine, loading GeoIP/GeoSite databases from `home_dir`.
    pub async fn with_home_dir(
        rule_strings: &[RuleString],
        providers: &HashMap<String, RuleProviderConfig>,
        home_dir: &Path,
    ) -> Result<Self> {
        let mut rules = Vec::new();

        let geoip_matcher = geoip::GeoIpMatcher::new(home_dir);
        let geosite_matcher = geosite::GeoSiteMatcher::new(home_dir);

        // Collect the target associated with each RULE-SET reference so we can
        // assign provider rules to the correct proxy target.
        let mut ruleset_targets: HashMap<String, String> = HashMap::new();
        let mut provider_rules: HashMap<String, Vec<ParsedRule>> = HashMap::new();
        for rule_str in rule_strings {
            let trimmed = rule_str.trim();
            if trimmed.starts_with("RULE-SET,") {
                let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
                if parts.len() >= 3 {
                    ruleset_targets
                        .insert(parts[1].trim().to_string(), parts[2].trim().to_string());
                }
            }
        }

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

            let rp = provider::RuleProvider::new(
                name.clone(),
                &prov_config.provider_type,
                prov_config.url.clone(),
                path,
                prov_config.interval.unwrap_or(86400),
                prov_config.format.as_deref(),
            );

            if let Err(e) = rp.load().await {
                tracing::warn!("Failed to load rule provider '{}': {}", name, e);
                continue;
            }

            let loaded_rules = rp.rules().await;
            let behavior = prov_config.behavior.as_deref().unwrap_or("domain");
            let target = ruleset_targets
                .get(name)
                .cloned()
                .unwrap_or_else(|| "DIRECT".to_string());

            tracing::info!(
                "Merging rule provider '{}' ({} behavior, {} rules) -> target '{}'",
                name,
                behavior,
                loaded_rules.len(),
                target
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
                        // ".example.com"  → match subdomains only (DOMAIN-SUFFIX for ".example.com")
                        // "example.com"   → exact match only (DOMAIN)
                        let cleaned = payload
                            .trim_start_matches("'")
                            .trim_end_matches("'");
                        if cleaned.starts_with("+.") {
                            let suffix = cleaned[2..].to_lowercase();
                            if !suffix.is_empty() {
                                provider_rules
                                    .entry(name.clone())
                                    .or_default()
                                    .push(ParsedRule {
                                        rule_type: "DOMAIN-SUFFIX".to_string(),
                                        payload: suffix,
                                        target: target.clone(),
                                        params: vec![],
                                    });
                            }
                        } else if cleaned.starts_with('.') {
                            let suffix = cleaned[1..].to_lowercase();
                            if !suffix.is_empty() {
                                // Dot-prefix means subdomains only — DOMAIN-SUFFIX
                                // matches "sub.example.com" but NOT "example.com" itself.
                                // We use a special synthetic rule type handled in matching.
                                provider_rules
                                    .entry(name.clone())
                                    .or_default()
                                    .push(ParsedRule {
                                        rule_type: "DOMAIN-SUFFIX-STRICT".to_string(),
                                        payload: suffix,
                                        target: target.clone(),
                                        params: vec![],
                                    });
                            }
                        } else {
                            let domain_val = cleaned.to_lowercase();
                            if !domain_val.is_empty() {
                                provider_rules
                                    .entry(name.clone())
                                    .or_default()
                                    .push(ParsedRule {
                                        rule_type: "DOMAIN".to_string(),
                                        payload: domain_val,
                                        target: target.clone(),
                                        params: vec![],
                                    });
                            }
                        }
                    }
                    "ipcidr" => {
                        provider_rules
                            .entry(name.clone())
                            .or_default()
                            .push(ParsedRule {
                                rule_type: "IP-CIDR".to_string(),
                                payload: payload.to_string(),
                                target: target.clone(),
                                params: vec![],
                            });
                    }
                    "classical" => {
                        // mihomo compat: provider rules have no target — the target
                        // comes from the RULE-SET definition. Options like "no-resolve"
                        // go into params. ParseRulePayload(rule, needTarget=false).
                        if let Ok(mut parsed) = parse_provider_rule(payload) {
                            parsed.target = target.clone();
                            provider_rules.entry(name.clone()).or_default().push(parsed);
                        }
                    }
                    other => {
                        tracing::warn!("Unknown rule provider behavior '{}' for '{}'", other, name);
                    }
                }
            }
        }

        for rule_str in rule_strings {
            let parsed = parse_rule(rule_str)?;

            // Warn on unknown rule types
            if !matches!(
                parsed.rule_type.as_str(),
                "DOMAIN"
                    | "DOMAIN-SUFFIX"
                    | "DOMAIN-KEYWORD"
                    | "GEOIP"
                    | "GEOSITE"
                    | "DST-PORT"
                    | "SRC-PORT"
                    | "IN-PORT"
                    | "NETWORK"
                    | "PROCESS-NAME"
                    | "PROCESS-PATH"
                    | "IP-CIDR"
                    | "IP-CIDR6"
                    | "SRC-IP-CIDR"
                    | "IP-ASN"
                    | "SRC-GEOIP"
                    | "SRC-ASN"
                    | "MATCH"
                    | "RULE-SET"
                    | "AND"
                    | "OR"
                    | "NOT"
                    | "DOMAIN-REGEX"
                    | "DOMAIN-WILDCARD"
            ) {
                tracing::warn!("Unknown rule type: {}", parsed.rule_type);
            }

            // For RULE-SET: expand provider rules inline at this position
            if parsed.rule_type == "RULE-SET" {
                if let Some(expanded) = provider_rules.get(&parsed.payload).cloned() {
                    rules.extend(expanded);
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
        })
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
        // Evaluate rules in CONFIG ORDER — first match wins.
        // This matches mihomo behavior where rule priority is determined by
        // position in the YAML file, not by rule type.
        //
        // We still use indexed data structures (domain trie, CIDR table, etc.)
        // for O(1) lookup within each rule, but the evaluation order follows
        // the original config sequence.
        for (i, rule) in self.rules.iter().enumerate() {
            // mihomo compat: skip disabled rules (toggled via PATCH /rules/disable)
            if self
                .rule_stats
                .get(i)
                .map_or(false, |s| s.disabled.load(Ordering::Relaxed))
            {
                continue;
            }

            if let Some(action) = self.match_single_rule(rule, metadata) {
                if let Some(stats) = self.rule_stats.get(i) {
                    stats.hit_count.fetch_add(1, Ordering::Relaxed);
                }
                return (action, rule.rule_type.clone(), rule.payload.clone());
            }
        }

        // Default: DIRECT
        (Action::Direct, "MATCH".to_string(), String::new())
    }

    /// Match a connection against the rule engine and return the action.
    pub fn match_rules(&self, metadata: &RuleMetadata) -> Action {
        self.match_rules_detailed(metadata).0
    }

    fn match_single_rule(&self, rule: &ParsedRule, metadata: &RuleMetadata) -> Option<Action> {
        match rule.rule_type.as_str() {
            "MATCH" => Some(target_to_action(&rule.target)),

            "NETWORK" => {
                if metadata.network.eq_ignore_ascii_case(&rule.payload) {
                    Some(target_to_action(&rule.target))
                } else {
                    None
                }
            }

            "SRC-PORT" => {
                if port_matches(metadata.src_port, &rule.payload) {
                    return Some(target_to_action(&rule.target));
                }
                None
            }

            "PROCESS-NAME" => {
                if let Some(ref name) = metadata.process_name {
                    if name == &rule.payload {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "PROCESS-PATH" => {
                if let Some(ref path) = metadata.process_path {
                    if path == &rule.payload {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "GEOIP" => {
                if let Some(ref ip) = metadata.dst_ip {
                    if let Some(country) = self.geoip_matcher.lookup_country(ip) {
                        let no_resolve = rule.params.iter().any(|p| p == "no-resolve");
                        let _ = no_resolve; // no-resolve only affects DNS, not matching
                        if country.eq_ignore_ascii_case(&rule.payload) {
                            return Some(target_to_action(&rule.target));
                        }
                    }
                }
                None
            }

            "SRC-GEOIP" => {
                if let Some(ref ip) = metadata.src_ip {
                    if let Some(country) = self.geoip_matcher.lookup_country(ip) {
                        if country.eq_ignore_ascii_case(&rule.payload) {
                            return Some(target_to_action(&rule.target));
                        }
                    }
                }
                None
            }

            "GEOSITE" => {
                if let Some(ref domain) = metadata.domain {
                    if self.geosite_matcher.lookup(domain, &rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "SRC-IP-CIDR" => {
                if let Some(ref ip) = metadata.src_ip {
                    if check_ip_in_cidr(ip, &rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DOMAIN-REGEX" => {
                // Basic pattern matching without full regex dependency.
                // Supports simple patterns: "^" (starts_with), "$" (ends_with),
                // ".*" (any substring). For full regex, add the `regex` crate.
                if let Some(ref domain) = metadata.domain {
                    if match_domain_regex(&rule.payload, domain) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "AND" => {
                // Syntax: AND,((RULE1),(RULE2),...),target
                // The payload contains the nested conditions like
                // "((DOMAIN-SUFFIX,google.com),(NETWORK,udp))"
                if match_logical_and(&rule.payload, metadata, self) {
                    Some(target_to_action(&rule.target))
                } else {
                    None
                }
            }

            "OR" => {
                if match_logical_or(&rule.payload, metadata, self) {
                    Some(target_to_action(&rule.target))
                } else {
                    None
                }
            }

            "NOT" => {
                // NOT,((RULE)),target -- true if the inner rule does NOT match
                if match_logical_not(&rule.payload, metadata, self) {
                    Some(target_to_action(&rule.target))
                } else {
                    None
                }
            }

            "DOMAIN" => {
                if let Some(ref domain) = metadata.domain {
                    let d = domain.to_lowercase();
                    if d == rule.payload {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DOMAIN-SUFFIX" => {
                if let Some(ref domain) = metadata.domain {
                    let d = domain.to_lowercase();
                    let s = &rule.payload; // already lowercase from parse time
                    if d == *s
                        || (d.len() > s.len()
                            && d.ends_with(s.as_str())
                            && d.as_bytes()[d.len() - s.len() - 1] == b'.')
                    {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            // mihomo compat: ".example.com" in domain-behavior providers
            // matches subdomains only (not the domain itself)
            "DOMAIN-SUFFIX-STRICT" => {
                if let Some(ref domain) = metadata.domain {
                    let d = domain.to_lowercase();
                    let s = &rule.payload; // already lowercase from parse time
                    if d.len() > s.len()
                        && d.ends_with(s.as_str())
                        && d.as_bytes()[d.len() - s.len() - 1] == b'.'
                    {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DOMAIN-KEYWORD" => {
                if let Some(ref domain) = metadata.domain {
                    if domain.to_lowercase().contains(&rule.payload[..]) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DOMAIN-WILDCARD" => {
                if let Some(ref domain) = metadata.domain {
                    if wildcard_match(&rule.payload, &domain.to_lowercase()) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "IP-ASN" => {
                if let Some(ref ip) = metadata.dst_ip {
                    if let Some(asn) = self.geoip_matcher.lookup_asn(ip) {
                        if let Ok(rule_asn) = rule.payload.parse::<u32>() {
                            if asn == rule_asn {
                                return Some(target_to_action(&rule.target));
                            }
                        }
                    }
                }
                None
            }

            "SRC-IP-ASN" => {
                if let Some(ref ip) = metadata.src_ip {
                    if let Some(asn) = self.geoip_matcher.lookup_asn(ip) {
                        if let Ok(rule_asn) = rule.payload.parse::<u32>() {
                            if asn == rule_asn {
                                return Some(target_to_action(&rule.target));
                            }
                        }
                    }
                }
                None
            }

            "IP-SUFFIX" => {
                if let Some(ref ip) = metadata.dst_ip {
                    if check_ip_suffix(ip, &rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "SRC-IP-SUFFIX" => {
                if let Some(ref ip) = metadata.src_ip {
                    if check_ip_suffix(ip, &rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "PROCESS-NAME-WILDCARD" => {
                if let Some(ref name) = metadata.process_name {
                    if wildcard_match(&rule.payload, name) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "PROCESS-PATH-WILDCARD" => {
                if let Some(ref path) = metadata.process_path {
                    if wildcard_match(&rule.payload, path) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "IP-CIDR" | "IP-CIDR6" => {
                if let Some(ref ip) = metadata.dst_ip {
                    if check_ip_in_cidr(ip, &rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DST-PORT" => {
                if port_matches(metadata.dst_port, &rule.payload) {
                    return Some(target_to_action(&rule.target));
                }
                None
            }

            "IN-PORT" => {
                if let Some(in_port) = metadata.in_port {
                    if port_matches(in_port, &rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "IN-TYPE" => {
                if let Some(ref in_type) = metadata.in_type {
                    if in_type.eq_ignore_ascii_case(&rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "IN-USER" => {
                if let Some(ref in_user) = metadata.in_user {
                    if in_user == &rule.payload {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "IN-NAME" => {
                if let Some(ref in_name) = metadata.in_name {
                    if in_name == &rule.payload {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "UID" => {
                if let Some(uid) = metadata.uid {
                    if let Ok(rule_uid) = rule.payload.parse::<u32>() {
                        if uid == rule_uid {
                            return Some(target_to_action(&rule.target));
                        }
                    }
                }
                None
            }

            "DSCP" => {
                if let Some(dscp) = metadata.dscp {
                    if let Ok(rule_dscp) = rule.payload.parse::<u8>() {
                        if dscp == rule_dscp {
                            return Some(target_to_action(&rule.target));
                        }
                    }
                }
                None
            }

            "SUB-RULE" => {
                // SUB-RULE,sub-rule-group-name,target
                // Evaluate the named sub-rule group. If any sub-rule matches,
                // return its action. Otherwise fall through.
                if let Some(sub_rules) = self.sub_rules.get(&rule.payload) {
                    for sub_rule in sub_rules {
                        if let Some(action) = self.match_single_rule(sub_rule, metadata) {
                            return Some(action);
                        }
                    }
                }
                None
            }

            _ => None,
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

    /// Check if the GeoIP database is loaded.
    pub fn has_geoip(&self) -> bool {
        self.geoip_matcher.is_loaded()
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
                    if self.geoip_matcher.is_loaded() { 0 } else { -1 }
                }
            }
            "GEOSITE" => {
                self.geosite_matcher.record_count(payload) as i64
            }
            _ => -1,
        }
    }
}

// ---------------------------------------------------------------------------
// Rule parsing
// ---------------------------------------------------------------------------

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

/// Core rule parser matching mihomo's ParseRulePayload(ruleRaw, needTarget).
fn parse_rule_payload(rule_str: &str, need_target: bool) -> Result<ParsedRule> {
    let trimmed = rule_str.trim();

    // Handle logical rules specially because their payloads contain commas
    if trimmed.starts_with("AND,") || trimmed.starts_with("OR,") || trimmed.starts_with("NOT,") {
        return parse_logical_rule(trimmed);
    }

    let items: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
    if items.is_empty() {
        return Err(anyhow::anyhow!("empty rule"));
    }

    let rule_type = items[0].to_uppercase();

    if items.len() == 1 {
        return Err(anyhow::anyhow!("invalid rule format: {rule_str}"));
    }

    // MATCH rule: "MATCH,target"
    if rule_type == "MATCH" {
        return Ok(ParsedRule {
            rule_type,
            payload: String::new(),
            target: items[1].to_string(),
            params: vec![],
        });
    }

    let mut payload = items[1].to_string();

    // Pre-lowercase domain payloads
    match rule_type.as_str() {
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX" => {
            payload = payload.to_lowercase();
        }
        _ => {}
    }

    let (target, params) = if items.len() > 2 {
        if need_target {
            // Main config: item[2] = target, item[3..] = params
            let target = items[2].to_string();
            let params: Vec<String> = items[3..].iter().map(|s| s.to_string()).collect();
            (target, params)
        } else {
            // Provider rule: no target, item[2..] = params (e.g. "no-resolve")
            let params: Vec<String> = items[2..].iter().map(|s| s.to_string()).collect();
            (String::new(), params)
        }
    } else {
        (String::new(), vec![])
    };

    Ok(ParsedRule {
        rule_type,
        payload,
        target,
        params,
    })
}

/// Parse logical rules: AND,((RULE1),(RULE2)),target
/// OR,((RULE1),(RULE2)),target
/// NOT,((RULE)),target
fn parse_logical_rule(rule_str: &str) -> Result<ParsedRule> {
    // Find the rule type
    let first_comma = rule_str
        .find(',')
        .ok_or_else(|| anyhow::anyhow!("invalid logical rule: {rule_str}"))?;
    let rule_type = rule_str[..first_comma].trim().to_string();
    let rest = &rule_str[first_comma + 1..];

    // The payload is everything inside the outermost ((...)) and the target is
    // after the closing parentheses. We need to find the matching closing '))'
    // by tracking nesting depth.
    let rest = rest.trim();
    if !rest.starts_with('(') {
        return Err(anyhow::anyhow!(
            "logical rule payload must start with '(': {rule_str}"
        ));
    }

    let mut depth = 0i32;
    let mut end_idx = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end_idx = i;
                    break;
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(anyhow::anyhow!(
            "unbalanced parentheses in logical rule: {rule_str}"
        ));
    }

    let payload = rest[..=end_idx].to_string();
    let after = rest[end_idx + 1..].trim_start_matches(',').trim();
    let target = after.to_string();

    Ok(ParsedRule {
        rule_type,
        payload,
        target,
        params: vec![],
    })
}

fn target_to_action(target: &str) -> Action {
    match target {
        "DIRECT" => Action::Direct,
        "REJECT" => Action::Reject,
        "REJECT-DROP" => Action::RejectDrop,
        name => Action::Proxy(name.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Port range matching (mihomo compat: common/utils/ranges.go)
// ---------------------------------------------------------------------------

/// Parse mihomo-style port specification: "80", "80/443", "1000-2000", "80-90/443/8080-9090"
/// Also supports comma as separator (mihomo normalizes "," to "/").
fn parse_port_spec(spec: &str) -> Vec<(u16, u16)> {
    let mut ranges = Vec::new();
    // mihomo compat: commas are treated as slashes
    let normalized = spec.replace(',', "/");
    for part in normalized.split('/') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                ranges.push((s, e));
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ranges.push((p, p));
        }
    }
    ranges
}

/// Check if a port matches a mihomo-style port spec (single, multi, range, or combined).
fn port_matches(port: u16, spec: &str) -> bool {
    let ranges = parse_port_spec(spec);
    if ranges.is_empty() {
        // mihomo compat: empty ranges match everything
        return true;
    }
    ranges.iter().any(|&(start, end)| port >= start && port <= end)
}

// ---------------------------------------------------------------------------
// Domain regex (using the regex crate, matching mihomo behavior)
// ---------------------------------------------------------------------------

/// Match a domain against a regex pattern using the `regex` crate.
/// mihomo uses Go's regexp package which is RE2-based, similar to Rust's regex crate.
fn match_domain_regex(pattern: &str, domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    if let Ok(re) = Regex::new(pattern) {
        re.is_match(&domain_lower)
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Logical rule matching (AND, OR, NOT)
// ---------------------------------------------------------------------------

/// Parse the inner conditions from a logical rule payload.
/// Input like `((DOMAIN-SUFFIX,google.com),(NETWORK,udp))` returns
/// vec!["DOMAIN-SUFFIX,google.com", "NETWORK,udp"].
fn parse_logical_conditions(payload: &str) -> Vec<String> {
    let mut conditions = Vec::new();
    let trimmed = payload.trim();

    // Strip the outer parentheses
    let inner = if trimmed.starts_with('(') && trimmed.ends_with(')') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    // Now parse comma-separated conditions, each wrapped in ()
    let mut depth = 0i32;
    let mut start = 0;
    for (i, ch) in inner.char_indices() {
        match ch {
            '(' => {
                if depth == 0 {
                    start = i + 1; // content starts after '('
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let cond = inner[start..i].trim().to_string();
                    if !cond.is_empty() {
                        conditions.push(cond);
                    }
                }
            }
            _ => {}
        }
    }

    conditions
}

/// Evaluate a single condition string (e.g. "DOMAIN-SUFFIX,google.com") against metadata.
fn eval_condition(condition: &str, metadata: &RuleMetadata, engine: &RuleEngine) -> bool {
    let parts: Vec<&str> = condition.splitn(2, ',').collect();
    if parts.len() < 2 {
        return false;
    }
    let rule_type = parts[0].trim();
    let payload = parts[1].trim();

    match rule_type {
        "DOMAIN" => {
            if let Some(ref domain) = metadata.domain {
                domain.to_lowercase() == payload.to_lowercase()
            } else {
                false
            }
        }
        "DOMAIN-SUFFIX" => {
            if let Some(ref domain) = metadata.domain {
                let d = domain.to_lowercase();
                let p = payload.to_lowercase();
                d.ends_with(&format!(".{p}")) || d == p
            } else {
                false
            }
        }
        "DOMAIN-SUFFIX-STRICT" => {
            if let Some(ref domain) = metadata.domain {
                let d = domain.to_lowercase();
                let p = payload.to_lowercase();
                d.ends_with(&format!(".{p}"))
            } else {
                false
            }
        }
        "DOMAIN-KEYWORD" => {
            if let Some(ref domain) = metadata.domain {
                domain.to_lowercase().contains(&payload.to_lowercase())
            } else {
                false
            }
        }
        "DOMAIN-REGEX" => {
            if let Some(ref domain) = metadata.domain {
                match_domain_regex(payload, domain)
            } else {
                false
            }
        }
        "IP-CIDR" | "IP-CIDR6" => {
            if let Some(ref ip) = metadata.dst_ip {
                // Quick CIDR check
                check_ip_in_cidr(ip, payload)
            } else {
                false
            }
        }
        "SRC-IP-CIDR" => {
            if let Some(ref ip) = metadata.src_ip {
                check_ip_in_cidr(ip, payload)
            } else {
                false
            }
        }
        "GEOIP" => {
            if let Some(ref ip) = metadata.dst_ip {
                engine
                    .geoip_matcher
                    .lookup_country(ip)
                    .map(|c| c.eq_ignore_ascii_case(payload))
                    .unwrap_or(false)
            } else {
                false
            }
        }
        "GEOSITE" => {
            if let Some(ref domain) = metadata.domain {
                engine.geosite_matcher.lookup(domain, payload)
            } else {
                false
            }
        }
        "NETWORK" => metadata.network.eq_ignore_ascii_case(payload),
        "DST-PORT" => port_matches(metadata.dst_port, payload),
        "SRC-PORT" => port_matches(metadata.src_port, payload),
        "PROCESS-NAME" => metadata
            .process_name
            .as_ref()
            .map(|n| n == payload)
            .unwrap_or(false),
        "PROCESS-PATH" => metadata
            .process_path
            .as_ref()
            .map(|p| p == payload)
            .unwrap_or(false),
        _ => false,
    }
}

fn match_logical_and(payload: &str, metadata: &RuleMetadata, engine: &RuleEngine) -> bool {
    let conditions = parse_logical_conditions(payload);
    if conditions.is_empty() {
        return false;
    }
    conditions
        .iter()
        .all(|c| eval_condition(c, metadata, engine))
}

fn match_logical_or(payload: &str, metadata: &RuleMetadata, engine: &RuleEngine) -> bool {
    let conditions = parse_logical_conditions(payload);
    if conditions.is_empty() {
        return false;
    }
    conditions
        .iter()
        .any(|c| eval_condition(c, metadata, engine))
}

fn match_logical_not(payload: &str, metadata: &RuleMetadata, engine: &RuleEngine) -> bool {
    let conditions = parse_logical_conditions(payload);
    if conditions.is_empty() {
        return false;
    }
    // NOT applies to the first (and typically only) condition
    !eval_condition(&conditions[0], metadata, engine)
}

// ---------------------------------------------------------------------------
// Helper: inline CIDR check for logical rules
// ---------------------------------------------------------------------------

fn check_ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match ip {
        IpAddr::V4(v4) => {
            if let Ok(network) = parts[0].parse::<std::net::Ipv4Addr>() {
                let ip_u32 = u32::from(*v4);
                let net_u32 = u32::from(network);
                if prefix_len == 0 {
                    true
                } else if prefix_len >= 32 {
                    ip_u32 == net_u32
                } else {
                    let mask = !((1u32 << (32 - prefix_len)) - 1);
                    (ip_u32 & mask) == (net_u32 & mask)
                }
            } else {
                false
            }
        }
        IpAddr::V6(v6) => {
            if let Ok(network) = parts[0].parse::<std::net::Ipv6Addr>() {
                let ip_u128 = u128::from(*v6);
                let net_u128 = u128::from(network);
                if prefix_len == 0 {
                    true
                } else if prefix_len >= 128 {
                    ip_u128 == net_u128
                } else {
                    let mask = !((1u128 << (128 - prefix_len)) - 1);
                    (ip_u128 & mask) == (net_u128 & mask)
                }
            } else {
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wildcard matching (*, ?)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// IP suffix matching
// ---------------------------------------------------------------------------

fn check_ip_suffix(ip: &IpAddr, suffix: &str) -> bool {
    // IP-SUFFIX format: "1.2.3.0/24" means the last 24 bits match
    // Or just a plain IP suffix string
    let parts: Vec<&str> = suffix.split('/').collect();
    if parts.len() != 2 {
        return ip.to_string().ends_with(suffix);
    }
    // If it has /prefix, treat as CIDR
    check_ip_in_cidr(ip, suffix)
}

// ---------------------------------------------------------------------------
// Default home dir (same logic as main.rs)
// ---------------------------------------------------------------------------

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
    fn parse_logical_conditions_test() {
        let conditions = parse_logical_conditions("((DOMAIN-SUFFIX,google.com),(NETWORK,udp))");
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0], "DOMAIN-SUFFIX,google.com");
        assert_eq!(conditions[1], "NETWORK,udp");
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
    fn parse_port_spec_ignores_invalid_parts() {
        let ranges = parse_port_spec("80/abc/443");
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (80, 80));
        assert_eq!(ranges[1], (443, 443));
    }

    // -----------------------------------------------------------------------
    // Domain regex with real regex crate tests
    // -----------------------------------------------------------------------

    #[test]
    fn match_domain_regex_character_class() {
        // Real regex features that the old basic matcher couldn't handle
        assert!(match_domain_regex(r"^(www|api)\.example\.com$", "www.example.com"));
        assert!(match_domain_regex(r"^(www|api)\.example\.com$", "api.example.com"));
        assert!(!match_domain_regex(r"^(www|api)\.example\.com$", "cdn.example.com"));
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
}
