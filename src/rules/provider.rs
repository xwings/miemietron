use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Rule provider that fetches rules from HTTP URLs or local files.
///
/// Supports formats:
/// - "text": One rule payload per line (e.g. domain suffixes, CIDRs)
/// - "yaml": A YAML file with a `payload` list
/// - "mrs": Placeholder for mihomo binary rule-set format (not yet implemented)
pub struct RuleProvider {
    name: String,
    provider_type: ProviderType,
    format: RuleFormat,
    url: Option<String>,
    path: Option<PathBuf>,
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
    ) -> Self {
        let provider_type = match provider_type {
            "http" => ProviderType::Http,
            _ => ProviderType::File,
        };

        let format = match format {
            Some("yaml") => RuleFormat::Yaml,
            Some("mrs") => RuleFormat::Mrs,
            _ => RuleFormat::Text,
        };

        Self {
            name,
            provider_type,
            format,
            url,
            path,
            interval,
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Load rules from the configured source (file or cached HTTP response).
    pub async fn load(&self) -> Result<()> {
        let content = match self.provider_type {
            ProviderType::File => {
                let path = self
                    .path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("file provider {} has no path", self.name))?;
                tokio::fs::read_to_string(path).await?
            }
            ProviderType::Http => {
                // Try local cache first
                if let Some(ref path) = self.path {
                    if path.exists() {
                        tokio::fs::read_to_string(path).await?
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
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured update interval in seconds.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    async fn fetch_remote(&self) -> Result<String> {
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
        Ok(resp.text().await?)
    }

    fn parse_content(&self, content: &str) -> Result<Vec<String>> {
        match self.format {
            RuleFormat::Text => Ok(parse_text_format(content)),
            RuleFormat::Yaml => parse_yaml_format(content),
            RuleFormat::Mrs => {
                tracing::warn!(
                    "MRS binary format not yet implemented for provider '{}'",
                    self.name
                );
                Ok(Vec::new())
            }
        }
    }
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
        .map_err(|e| anyhow::anyhow!("failed to parse YAML rule provider: {}", e))?;

    Ok(parsed
        .payload
        .into_iter()
        .map(|s| {
            // YAML payload lines may include leading "+ " or "- " prefixes
            let s = s.trim();
            if let Some(stripped) = s.strip_prefix("'+.") {
                // Common pattern: '+.domain.com' means DOMAIN-SUFFIX
                stripped.trim_end_matches('\'').to_string()
            } else if let Some(stripped) = s.strip_prefix('+') {
                stripped.trim_start_matches('.').to_string()
            } else {
                s.to_string()
            }
        })
        .filter(|s| !s.is_empty())
        .collect())
}
