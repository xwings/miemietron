use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    #[serde(default)]
    pub enable: bool,

    #[serde(default = "default_listen")]
    pub listen: String,

    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub prefer_h3: bool,
    #[serde(default = "default_true")]
    pub use_hosts: bool,
    #[serde(default = "default_true")]
    pub use_system_hosts: bool,
    #[serde(default)]
    pub respect_rules: bool,

    // Enhanced mode
    #[serde(default = "default_enhanced_mode")]
    pub enhanced_mode: String,
    #[serde(default = "default_fake_ip_range")]
    pub fake_ip_range: String,
    #[serde(default)]
    pub fake_ip_range6: Option<String>,
    #[serde(default = "default_fake_ip_ttl")]
    pub fake_ip_ttl: u32,
    #[serde(default)]
    pub fake_ip_filter: Vec<String>,
    #[serde(default = "default_filter_mode")]
    pub fake_ip_filter_mode: String,

    // Servers
    #[serde(default = "default_nameservers")]
    pub default_nameserver: Vec<String>,
    #[serde(default)]
    pub nameserver: Vec<String>,
    #[serde(default)]
    pub fallback: Vec<String>,
    #[serde(default)]
    pub fallback_filter: Option<FallbackFilter>,

    // Policy routing
    #[serde(default)]
    pub nameserver_policy: HashMap<String, serde_yaml::Value>,

    // Proxy DNS
    #[serde(default)]
    pub proxy_server_nameserver: Vec<String>,
    #[serde(default)]
    pub proxy_server_nameserver_policy: HashMap<String, serde_yaml::Value>,

    // Direct DNS
    #[serde(default)]
    pub direct_nameserver: Vec<String>,
    #[serde(default)]
    pub direct_nameserver_follow_policy: bool,

    // Cache
    #[serde(default = "default_cache_algorithm")]
    pub cache_algorithm: String,
    #[serde(default)]
    pub cache_max_size: u32,

    // Catch-all
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct FallbackFilter {
    #[serde(default)]
    pub geoip: bool,
    #[serde(default = "default_geoip_code")]
    pub geoip_code: String,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: default_listen(),
            ipv6: false,
            prefer_h3: false,
            use_hosts: true,
            use_system_hosts: true,
            respect_rules: false,
            enhanced_mode: default_enhanced_mode(),
            fake_ip_range: default_fake_ip_range(),
            fake_ip_range6: None,
            fake_ip_ttl: default_fake_ip_ttl(),
            fake_ip_filter: vec![],
            fake_ip_filter_mode: default_filter_mode(),
            default_nameserver: default_nameservers(),
            nameserver: vec![],
            fallback: vec![],
            fallback_filter: None,
            nameserver_policy: HashMap::new(),
            proxy_server_nameserver: vec![],
            proxy_server_nameserver_policy: HashMap::new(),
            direct_nameserver: vec![],
            direct_nameserver_follow_policy: false,
            cache_algorithm: default_cache_algorithm(),
            cache_max_size: 0,
            extra: HashMap::new(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:1053".to_string()
}

fn default_true() -> bool {
    true
}

fn default_enhanced_mode() -> String {
    "fake-ip".to_string()
}

fn default_fake_ip_range() -> String {
    "198.18.0.0/15".to_string()
}

fn default_fake_ip_ttl() -> u32 {
    3600
}

fn default_filter_mode() -> String {
    "blacklist".to_string()
}

fn default_nameservers() -> Vec<String> {
    vec!["114.114.114.114".to_string(), "8.8.8.8".to_string()]
}

fn default_cache_algorithm() -> String {
    "arc".to_string()
}

fn default_geoip_code() -> String {
    "CN".to_string()
}
