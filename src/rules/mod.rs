pub mod domain;
pub mod geoip;
pub mod geosite;
pub mod ipcidr;
pub mod process;
pub mod provider;

use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

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
    domain_matcher: domain::DomainMatcher,
    cidr_matcher: ipcidr::CidrMatcher,
    src_cidr_matcher: ipcidr::CidrMatcher,
    port_rules: HashMap<u16, String>, // dst_port -> target
    geoip_matcher: geoip::GeoIpMatcher,
    geosite_matcher: geosite::GeoSiteMatcher,
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
        let mut domain_exact = HashMap::new();
        let mut domain_suffixes = Vec::new();
        let mut domain_keywords = Vec::new();
        let mut cidrs = Vec::new();
        let mut src_cidrs = Vec::new();
        let mut port_rules = HashMap::new();

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
                        let domain_val = payload
                            .trim_start_matches("+.")
                            .trim_start_matches("'")
                            .trim_end_matches("'")
                            .to_lowercase();
                        if !domain_val.is_empty() {
                            domain_suffixes.push((domain_val.clone(), target.clone()));
                            // Also store for inline expansion
                            provider_rules
                                .entry(name.clone())
                                .or_default()
                                .push(ParsedRule {
                                    rule_type: "DOMAIN-SUFFIX".to_string(),
                                    payload: domain_val,
                                    target: target.clone(),
                                    params: vec![],
                                });
                        }
                    }
                    "ipcidr" => {
                        cidrs.push((payload.to_string(), target.clone()));
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
                        // Each line is a full rule string, e.g. "DOMAIN-SUFFIX,google.com"
                        let full_rule = if payload.matches(',').count() >= 2 {
                            payload.to_string()
                        } else {
                            format!("{payload},{target}")
                        };

                        if let Ok(parsed) = parse_rule(&full_rule) {
                            // Store in provider_rules for later inline expansion
                            // at the RULE-SET position in the main rules list
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

            match parsed.rule_type.as_str() {
                "DOMAIN" => {
                    domain_exact.insert(parsed.payload.clone(), parsed.target.clone());
                }
                "DOMAIN-SUFFIX" => {
                    domain_suffixes.push((parsed.payload.clone(), parsed.target.clone()));
                }
                "DOMAIN-KEYWORD" => {
                    domain_keywords.push((parsed.payload.clone(), parsed.target.clone()));
                }
                "IP-CIDR" | "IP-CIDR6" => {
                    cidrs.push((parsed.payload.clone(), parsed.target.clone()));
                }
                "SRC-IP-CIDR" => {
                    src_cidrs.push((parsed.payload.clone(), parsed.target.clone()));
                }
                "GEOIP" => {
                    // Handled at match time via geoip_matcher
                }
                "GEOSITE" => {
                    // Handled at match time via geosite_matcher
                }
                "DST-PORT" => {
                    if let Ok(port) = parsed.payload.parse::<u16>() {
                        port_rules.insert(port, parsed.target.clone());
                    }
                }
                "SRC-PORT" | "IN-PORT" | "NETWORK" | "PROCESS-NAME" | "PROCESS-PATH" | "IP-ASN"
                | "SRC-GEOIP" | "SRC-ASN" | "MATCH" | "RULE-SET" | "AND" | "OR" | "NOT"
                | "DOMAIN-REGEX" | "DOMAIN-WILDCARD" | "UID" | "IN-TYPE" | "IN-USER"
                | "IN-NAME" | "DSCP" | "SUB-RULE" | "IP-SUFFIX" => {
                    // Store as generic rule for sequential fallback
                }
                other => {
                    tracing::warn!("Unknown rule type: {}", other);
                }
            }

            // For RULE-SET: expand provider rules inline at this position
            if parsed.rule_type == "RULE-SET" {
                if let Some(expanded) = provider_rules.remove(&parsed.payload) {
                    rules.extend(expanded);
                }
                // Don't push the RULE-SET rule itself — it's been expanded
            } else {
                rules.push(parsed);
            }
        }

        let domain_matcher =
            domain::DomainMatcher::new(domain_exact, domain_suffixes, domain_keywords);
        let cidr_matcher = ipcidr::CidrMatcher::new(cidrs);
        let src_cidr_matcher = ipcidr::CidrMatcher::new(src_cidrs);

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

        Ok(Self {
            rules,
            domain_matcher,
            cidr_matcher,
            src_cidr_matcher,
            port_rules,
            geoip_matcher,
            geosite_matcher,
        })
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
        for rule in &self.rules {
            if let Some(action) = self.match_single_rule(rule, metadata) {
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
                if let Ok(port) = rule.payload.parse::<u16>() {
                    if metadata.src_port == port {
                        return Some(target_to_action(&rule.target));
                    }
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
                // Also check in sequential path for SRC-IP-CIDR rules that
                // weren't added to the dedicated matcher (shouldn't happen,
                // but provides safety net)
                if let Some(ref ip) = metadata.src_ip {
                    if let Some(target) = self.src_cidr_matcher.lookup(ip) {
                        return Some(target_to_action(&target));
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
                    if domain.eq_ignore_ascii_case(&rule.payload) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DOMAIN-SUFFIX" => {
                if let Some(ref domain) = metadata.domain {
                    let d = domain.to_lowercase();
                    let s = rule.payload.to_lowercase();
                    if d == s || d.ends_with(&format!(".{s}")) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "DOMAIN-KEYWORD" => {
                if let Some(ref domain) = metadata.domain {
                    if domain.to_lowercase().contains(&rule.payload.to_lowercase()) {
                        return Some(target_to_action(&rule.target));
                    }
                }
                None
            }

            "IP-CIDR" | "IP-CIDR6" => {
                if let Some(ref ip) = metadata.dst_ip {
                    if let Some(target) = self.cidr_matcher.lookup(ip) {
                        if target == rule.target {
                            return Some(target_to_action(&rule.target));
                        }
                    }
                }
                None
            }

            "DST-PORT" => {
                if let Ok(port) = rule.payload.parse::<u16>() {
                    if metadata.dst_port == port {
                        return Some(target_to_action(&rule.target));
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

    /// Check if the GeoIP database is loaded.
    pub fn has_geoip(&self) -> bool {
        self.geoip_matcher.is_loaded()
    }

    /// Get a reference to the GeoIP matcher (for DNS fallback filtering, etc.)
    pub fn geoip_matcher(&self) -> &geoip::GeoIpMatcher {
        &self.geoip_matcher
    }
}

// ---------------------------------------------------------------------------
// Rule parsing
// ---------------------------------------------------------------------------

fn parse_rule(rule_str: &str) -> Result<ParsedRule> {
    let trimmed = rule_str.trim();

    // Handle logical rules specially because their payloads contain commas
    if trimmed.starts_with("AND,") || trimmed.starts_with("OR,") || trimmed.starts_with("NOT,") {
        return parse_logical_rule(trimmed);
    }

    let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
    match parts.len() {
        2 => Ok(ParsedRule {
            rule_type: parts[0].trim().to_string(),
            payload: String::new(),
            target: parts[1].trim().to_string(),
            params: vec![],
        }),
        3 => {
            let target_and_params: Vec<&str> = parts[2].split(',').collect();
            Ok(ParsedRule {
                rule_type: parts[0].trim().to_string(),
                payload: parts[1].trim().to_string(),
                target: target_and_params[0].trim().to_string(),
                params: target_and_params[1..]
                    .iter()
                    .map(|s| s.trim().to_string())
                    .collect(),
            })
        }
        _ => Err(anyhow::anyhow!("invalid rule format: {rule_str}")),
    }
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
// Domain regex (basic pattern matching without the regex crate)
// ---------------------------------------------------------------------------

/// Simple domain pattern matching.
///
/// Supports a subset of regex-like patterns:
/// - Literal string: exact substring match
/// - `^pattern`: starts with
/// - `pattern$`: ends with
/// - `^pattern$`: exact match
/// - `.` matches any single char (only the literal dot is used in domain patterns)
/// - `.*` is treated as "any substring" wildcard
///
/// This avoids pulling in the full `regex` crate for basic use cases.
fn match_domain_regex(pattern: &str, domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    let pat = pattern.to_lowercase();

    let starts_anchor = pat.starts_with('^');
    let ends_anchor = pat.ends_with('$');

    let inner = pat.trim_start_matches('^').trim_end_matches('$');

    // If the pattern contains ".*", split on it and check parts
    if inner.contains(".*") {
        let parts: Vec<&str> = inner.split(".*").collect();
        // All parts must appear in order in the domain
        let mut search_from = 0usize;

        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if i == 0 && starts_anchor {
                if !domain_lower.starts_with(part) {
                    return false;
                }
                search_from = part.len();
            } else if i == parts.len() - 1 && ends_anchor {
                if !domain_lower[search_from..].ends_with(part) {
                    return false;
                }
            } else {
                match domain_lower[search_from..].find(part) {
                    Some(pos) => search_from += pos + part.len(),
                    None => return false,
                }
            }
        }
        return true;
    }

    // Simple case: no wildcards
    if starts_anchor && ends_anchor {
        domain_lower == inner
    } else if starts_anchor {
        domain_lower.starts_with(inner)
    } else if ends_anchor {
        domain_lower.ends_with(inner)
    } else {
        domain_lower.contains(inner)
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
        "DST-PORT" => {
            if let Ok(port) = payload.parse::<u16>() {
                metadata.dst_port == port
            } else {
                false
            }
        }
        "SRC-PORT" => {
            if let Ok(port) = payload.parse::<u16>() {
                metadata.src_port == port
            } else {
                false
            }
        }
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
}
