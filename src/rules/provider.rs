use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Rule provider that fetches rules from HTTP URLs or local files.
///
/// Supports formats:
/// - "text": One rule payload per line (e.g. domain suffixes, CIDRs)
/// - "yaml": A YAML file with a `payload` list
/// - "mrs": mihomo's zstd-compressed binary rule-set (domain behavior only —
///   see `rules::mrs`)
pub struct RuleProvider {
    name: String,
    provider_type: ProviderType,
    format: RuleFormat,
    /// Provider behavior ("domain" / "ipcidr" / "classical") — needed by the
    /// MRS reader, which validates the file's behavior byte like mihomo.
    behavior: String,
    url: Option<String>,
    path: Option<PathBuf>,
    #[allow(dead_code)]
    interval: u64,
    rules: Arc<RwLock<Vec<String>>>,
}

#[derive(Debug, Clone, PartialEq)]
enum ProviderType {
    Http,
    File,
}

#[derive(Debug, Clone, PartialEq)]
enum RuleFormat {
    Text,
    Yaml,
    Mrs,
}

impl RuleProvider {
    /// Create a new rule provider from configuration.
    pub fn new(
        name: String,
        provider_type: &str,
        url: Option<String>,
        path: Option<PathBuf>,
        interval: u64,
        format: Option<&str>,
        behavior: &str,
    ) -> Self {
        let provider_type = match provider_type {
            "http" => ProviderType::Http,
            _ => ProviderType::File,
        };

        let format = match format {
            Some("text") => RuleFormat::Text,
            Some("mrs") => RuleFormat::Mrs,
            // mihomo defaults to YAML for rule providers
            _ => RuleFormat::Yaml,
        };

        Self {
            name,
            provider_type,
            format,
            behavior: behavior.to_string(),
            url,
            path,
            interval,
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Load rules from the configured source (file or cached HTTP response).
    pub async fn load(&self) -> Result<()> {
        // Read raw bytes: MRS providers are binary (zstd), not UTF-8 text.
        let content = match self.provider_type {
            ProviderType::File => {
                let path = self
                    .path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("file provider {} has no path", self.name))?;
                tokio::fs::read(path).await?
            }
            ProviderType::Http => {
                // Try local cache first
                if let Some(ref path) = self.path {
                    if path.exists() {
                        tokio::fs::read(path).await?
                    } else {
                        // Fetch from URL
                        self.fetch_remote().await?
                    }
                } else {
                    self.fetch_remote().await?
                }
            }
        };

        let parsed = self.parse_content(&content)?;
        let mut rules = self.rules.write().await;
        *rules = parsed;
        tracing::info!("Rule provider '{}' loaded {} rules", self.name, rules.len());
        Ok(())
    }

    /// Update rules by fetching from the remote URL (HTTP providers only).
    #[allow(dead_code)]
    pub async fn update(&self) -> Result<()> {
        if self.provider_type != ProviderType::Http {
            return Ok(());
        }

        let content = self.fetch_remote().await?;

        // Save to local cache
        if let Some(ref path) = self.path {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.ok();
            }
            tokio::fs::write(path, &content).await.ok();
        }

        let parsed = self.parse_content(&content)?;
        let mut rules = self.rules.write().await;
        *rules = parsed;
        tracing::info!(
            "Rule provider '{}' updated with {} rules",
            self.name,
            rules.len()
        );
        Ok(())
    }

    /// Get the current list of rule payloads.
    pub async fn rules(&self) -> Vec<String> {
        self.rules.read().await.clone()
    }

    /// Start a background task that auto-updates on the configured interval.
    /// Returns a JoinHandle that can be used to cancel the task.
    #[allow(dead_code)]
    pub fn start_auto_update(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval_secs = if self.interval > 0 {
            self.interval
        } else {
            86400 // default: 24 hours
        };

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            // Skip the first tick (fires immediately)
            interval.tick().await;

            loop {
                interval.tick().await;
                if let Err(e) = self.update().await {
                    tracing::warn!("Failed to update rule provider '{}': {}", self.name, e);
                }
            }
        })
    }

    /// Get the provider name.
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured update interval in seconds.
    #[allow(dead_code)]
    pub fn interval(&self) -> u64 {
        self.interval
    }

    async fn fetch_remote(&self) -> Result<Vec<u8>> {
        let url = self
            .url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP provider '{}' has no URL", self.name))?;

        let resp = reqwest::get(url).await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP {} when fetching provider '{}'",
                resp.status(),
                self.name
            ));
        }
        Ok(resp.bytes().await?.to_vec())
    }

    fn parse_content(&self, content: &[u8]) -> Result<Vec<String>> {
        match self.format {
            RuleFormat::Text => Ok(parse_text_format(as_utf8(content, &self.name)?)),
            RuleFormat::Yaml => {
                let text = as_utf8(content, &self.name)?;
                // Try YAML first; fall back to text if YAML parsing fails
                match parse_yaml_format(text) {
                    Ok(rules) if !rules.is_empty() => Ok(rules),
                    _ => Ok(parse_text_format(text)),
                }
            }
            RuleFormat::Mrs => {
                // mihomo compat: mrs_reader.go — zstd stream wrapping the
                // behavior strategy's binary body. Only domain behavior is
                // implemented; anything else errors (never a silent text
                // fallback that would produce garbage rules).
                let expected = match self.behavior.as_str() {
                    "domain" => super::mrs::BEHAVIOR_DOMAIN,
                    other => {
                        return Err(anyhow::anyhow!(
                            "rule provider '{}': MRS {} behavior not supported (only domain)",
                            self.name,
                            other
                        ))
                    }
                };
                super::mrs::parse_mrs_domains(content, expected)
                    .map_err(|e| anyhow::anyhow!("rule provider '{}': {}", self.name, e))
            }
        }
    }
}

fn as_utf8<'a>(content: &'a [u8], name: &str) -> Result<&'a str> {
    std::str::from_utf8(content)
        .map_err(|_| anyhow::anyhow!("rule provider '{}' content is not valid UTF-8", name))
}

/// Parse text format: one rule payload per line, ignoring comments and blank lines.
fn parse_text_format(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
}

/// Parse YAML format: expects a `payload` key with a list of strings.
fn parse_yaml_format(content: &str) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct YamlRules {
        #[serde(default)]
        payload: Vec<String>,
    }

    let parsed: YamlRules = serde_yaml::from_str(content)
        .map_err(|e| anyhow::anyhow!("failed to parse YAML rule provider: {e}"))?;

    // mihomo compat: payload lines are fed verbatim into the behavior strategy
    // (rules/provider/provider.go rulesParse → domain trie). The `+.`/`.` suffix
    // markers are interpreted downstream by the behavior handler, so they MUST
    // NOT be stripped here — doing so silently degrades DOMAIN-SUFFIX to exact
    // DOMAIN match and breaks every Loyalsoldier-style domain list.
    Ok(parsed
        .payload
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_text_domain_one_per_line() {
        let content = "example.com\ngoogle.com\nyoutube.com\n";
        let rules = parse_text_format(content);
        assert_eq!(rules, vec!["example.com", "google.com", "youtube.com"]);
    }

    #[test]
    fn parse_text_ignores_comments_and_blank_lines() {
        let content = "# This is a comment\n\nexample.com\n  \n# Another comment\ngoogle.com\n";
        let rules = parse_text_format(content);
        assert_eq!(rules, vec!["example.com", "google.com"]);
    }

    #[test]
    fn parse_text_trims_whitespace() {
        let content = "  example.com  \n\tgoogle.com\t\n";
        let rules = parse_text_format(content);
        assert_eq!(rules, vec!["example.com", "google.com"]);
    }

    #[test]
    fn parse_text_empty_content() {
        let content = "";
        let rules = parse_text_format(content);
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_text_only_comments() {
        let content = "# comment 1\n# comment 2\n";
        let rules = parse_text_format(content);
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_text_ipcidr_behavior() {
        let content = "192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12\n";
        let rules = parse_text_format(content);
        assert_eq!(rules, vec!["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]);
    }

    #[test]
    fn parse_text_ipcidr_with_ipv6() {
        let content = "fc00::/7\n::1/128\n";
        let rules = parse_text_format(content);
        assert_eq!(rules, vec!["fc00::/7", "::1/128"]);
    }

    #[test]
    fn parse_text_classical_full_rule_strings() {
        let content = "\
DOMAIN-SUFFIX,google.com
DOMAIN-KEYWORD,youtube
IP-CIDR,192.168.0.0/16
DOMAIN,exact.example.com
";
        let rules = parse_text_format(content);
        assert_eq!(
            rules,
            vec![
                "DOMAIN-SUFFIX,google.com",
                "DOMAIN-KEYWORD,youtube",
                "IP-CIDR,192.168.0.0/16",
                "DOMAIN,exact.example.com",
            ]
        );
    }

    #[test]
    fn parse_text_classical_with_comments() {
        let content = "\
# Ad blocking rules
DOMAIN-SUFFIX,ads.example.com
# Tracking domains
DOMAIN-KEYWORD,tracker
";
        let rules = parse_text_format(content);
        assert_eq!(
            rules,
            vec!["DOMAIN-SUFFIX,ads.example.com", "DOMAIN-KEYWORD,tracker"]
        );
    }

    #[test]
    fn parse_yaml_domain_payload() {
        let content = r#"
payload:
  - "example.com"
  - "google.com"
  - "youtube.com"
"#;
        let rules = parse_yaml_format(content).unwrap();
        assert_eq!(rules, vec!["example.com", "google.com", "youtube.com"]);
    }

    #[test]
    fn parse_yaml_with_plus_dot_prefix() {
        // mihomo compat: `+.`/`.` suffix markers are preserved verbatim; the
        // behavior handler interprets them (DOMAIN-SUFFIX vs DOMAIN). Stripping
        // them here would silently downgrade suffix rules to exact matches.
        let content = r#"
payload:
  - "+.example.com"
  - "+.google.com"
  - "plain.com"
"#;
        let rules = parse_yaml_format(content).unwrap();
        assert_eq!(rules, vec!["+.example.com", "+.google.com", "plain.com"]);
    }

    #[test]
    fn parse_yaml_empty_payload() {
        let content = "payload: []\n";
        let rules = parse_yaml_format(content).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_yaml_missing_payload_key() {
        let content = "other-key: value\n";
        let rules = parse_yaml_format(content).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_yaml_ipcidr_payload() {
        let content = r#"
payload:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "fc00::/7"
"#;
        let rules = parse_yaml_format(content).unwrap();
        assert_eq!(rules, vec!["192.168.0.0/16", "10.0.0.0/8", "fc00::/7"]);
    }

    #[test]
    fn parse_yaml_classical_payload() {
        let content = r#"
payload:
  - "DOMAIN-SUFFIX,google.com"
  - "IP-CIDR,192.168.0.0/16"
  - "DOMAIN-KEYWORD,ads"
"#;
        let rules = parse_yaml_format(content).unwrap();
        assert_eq!(
            rules,
            vec![
                "DOMAIN-SUFFIX,google.com",
                "IP-CIDR,192.168.0.0/16",
                "DOMAIN-KEYWORD,ads",
            ]
        );
    }

    #[test]
    fn parse_yaml_invalid_yaml() {
        let content = "this is: [not: valid yaml: {{";
        assert!(parse_yaml_format(content).is_err());
    }

    #[test]
    fn rule_provider_new_http() {
        let provider = RuleProvider::new(
            "test".to_string(),
            "http",
            Some("https://example.com/rules.txt".to_string()),
            Some(PathBuf::from("/tmp/rules.txt")),
            3600,
            Some("text"),
            "domain",
        );
        assert_eq!(provider.name(), "test");
        assert_eq!(provider.interval(), 3600);
    }

    #[test]
    fn rule_provider_new_file() {
        let provider = RuleProvider::new(
            "local".to_string(),
            "file",
            None,
            Some(PathBuf::from("/etc/rules.txt")),
            0,
            Some("yaml"),
            "domain",
        );
        assert_eq!(provider.name(), "local");
        assert_eq!(provider.interval(), 0);
    }

    #[test]
    fn rule_provider_default_format_is_text() {
        let provider = RuleProvider::new("def".to_string(), "file", None, None, 0, None, "domain");
        // We can indirectly verify by parsing through the provider's parse_content
        let result = provider.parse_content(b"example.com\ngoogle.com").unwrap();
        assert_eq!(result, vec!["example.com", "google.com"]);
    }

    #[test]
    fn mrs_garbage_input_errors_not_silent_garbage() {
        // Invalid zstd input MUST surface as an explicit error instead of
        // producing junk text "rules".
        let provider = RuleProvider::new(
            "mrs".to_string(),
            "file",
            None,
            None,
            0,
            Some("mrs"),
            "domain",
        );
        let err = provider
            .parse_content(&[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x01, 0x02, 0x03])
            .expect_err("must error on invalid zstd MRS");
        let msg = format!("{err}");
        assert!(msg.contains("mrs"), "wrong error: {msg}");
    }

    #[test]
    fn mrs_ipcidr_behavior_rejected() {
        let provider = RuleProvider::new(
            "cnip".to_string(),
            "file",
            None,
            None,
            0,
            Some("mrs"),
            "ipcidr",
        );
        let err = provider
            .parse_content(&[0u8; 16])
            .expect_err("ipcidr mrs must be rejected");
        assert!(format!("{err}").contains("only domain"));
    }
}
