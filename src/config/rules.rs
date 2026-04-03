use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A rule string from the config, e.g. "DOMAIN-SUFFIX,google.com,Proxy"
pub type RuleString = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleProviderConfig {
    #[serde(rename = "type")]
    pub provider_type: String,

    #[serde(default)]
    pub behavior: Option<String>,

    #[serde(default)]
    pub url: Option<String>,

    #[serde(default)]
    pub path: Option<String>,

    #[serde(default)]
    pub interval: Option<u64>,

    #[serde(default)]
    pub format: Option<String>,

    // Catch-all
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}
