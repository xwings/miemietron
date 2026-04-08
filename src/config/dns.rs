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
    #[serde(default = "default_ipv6_timeout")]
    pub ipv6_timeout: u64,
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
    pub geosite: Vec<String>,
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
            ipv6_timeout: default_ipv6_timeout(),
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

fn default_ipv6_timeout() -> u64 {
    100
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dns_config_has_correct_defaults() {
        let yaml = "{}";
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(!config.enable);
        assert_eq!(config.listen, "0.0.0.0:1053");
        assert!(!config.ipv6);
        assert!(!config.prefer_h3);
        assert!(config.use_hosts);
        assert!(config.use_system_hosts);
        assert!(!config.respect_rules);
        assert_eq!(config.enhanced_mode, "fake-ip");
        assert_eq!(config.fake_ip_range, "198.18.0.0/15");
        assert_eq!(config.fake_ip_ttl, 3600);
        assert!(config.fake_ip_filter.is_empty());
        assert_eq!(config.fake_ip_filter_mode, "blacklist");
        assert_eq!(
            config.default_nameserver,
            vec!["114.114.114.114".to_string(), "8.8.8.8".to_string()]
        );
        assert!(config.nameserver.is_empty());
        assert!(config.fallback.is_empty());
        assert!(config.fallback_filter.is_none());
        assert!(config.nameserver_policy.is_empty());
        assert!(config.proxy_server_nameserver.is_empty());
        assert!(config.direct_nameserver.is_empty());
        assert!(!config.direct_nameserver_follow_policy);
        assert_eq!(config.cache_algorithm, "arc");
        assert_eq!(config.cache_max_size, 0);
    }

    #[test]
    fn full_dns_config_parses_all_fields() {
        let yaml = r#"
enable: true
listen: "127.0.0.1:5353"
ipv6: true
prefer-h3: true
use-hosts: false
use-system-hosts: false
respect-rules: true
enhanced-mode: redir-host
fake-ip-range: "10.0.0.0/8"
fake-ip-ttl: 7200
fake-ip-filter:
  - "*.lan"
  - "dns.msftncsi.com"
fake-ip-filter-mode: whitelist
default-nameserver:
  - "1.1.1.1"
nameserver:
  - "https://1.1.1.1/dns-query"
  - "tls://8.8.8.8:853"
fallback:
  - "https://1.0.0.1/dns-query"
fallback-filter:
  geoip: true
  geoip-code: US
  ipcidr:
    - "240.0.0.0/4"
  domain:
    - "+.google.com"
nameserver-policy:
  "geosite:cn": "114.114.114.114"
proxy-server-nameserver:
  - "https://1.1.1.1/dns-query"
direct-nameserver:
  - "114.114.114.114"
direct-nameserver-follow-policy: true
cache-algorithm: lru
cache-max-size: 1000
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.enable);
        assert_eq!(config.listen, "127.0.0.1:5353");
        assert!(config.ipv6);
        assert!(config.prefer_h3);
        assert!(!config.use_hosts);
        assert!(!config.use_system_hosts);
        assert!(config.respect_rules);
        assert_eq!(config.enhanced_mode, "redir-host");
        assert_eq!(config.fake_ip_range, "10.0.0.0/8");
        assert_eq!(config.fake_ip_ttl, 7200);
        assert_eq!(config.fake_ip_filter, vec!["*.lan", "dns.msftncsi.com"]);
        assert_eq!(config.fake_ip_filter_mode, "whitelist");
        assert_eq!(config.default_nameserver, vec!["1.1.1.1"]);
        assert_eq!(config.nameserver.len(), 2);
        assert_eq!(config.fallback.len(), 1);

        let ff = config.fallback_filter.as_ref().unwrap();
        assert!(ff.geoip);
        assert_eq!(ff.geoip_code, "US");
        assert_eq!(ff.ipcidr, vec!["240.0.0.0/4"]);
        assert_eq!(ff.domain, vec!["+.google.com"]);

        assert_eq!(config.nameserver_policy.len(), 1);
        assert_eq!(
            config.proxy_server_nameserver,
            vec!["https://1.1.1.1/dns-query"]
        );
        assert_eq!(config.direct_nameserver, vec!["114.114.114.114"]);
        assert!(config.direct_nameserver_follow_policy);
        assert_eq!(config.cache_algorithm, "lru");
        assert_eq!(config.cache_max_size, 1000);
    }

    #[test]
    fn default_trait_matches_serde_defaults() {
        let from_default = DnsConfig::default();
        let from_yaml: DnsConfig = serde_yaml::from_str("{}").unwrap();

        assert_eq!(from_default.enable, from_yaml.enable);
        assert_eq!(from_default.listen, from_yaml.listen);
        assert_eq!(from_default.enhanced_mode, from_yaml.enhanced_mode);
        assert_eq!(from_default.fake_ip_range, from_yaml.fake_ip_range);
        assert_eq!(from_default.fake_ip_ttl, from_yaml.fake_ip_ttl);
        assert_eq!(from_default.cache_algorithm, from_yaml.cache_algorithm);
        assert_eq!(
            from_default.default_nameserver,
            from_yaml.default_nameserver
        );
    }

    #[test]
    fn fallback_filter_defaults() {
        let yaml = "geoip: false";
        let ff: FallbackFilter = serde_yaml::from_str(yaml).unwrap();
        assert!(!ff.geoip);
        assert_eq!(ff.geoip_code, "CN");
        assert!(ff.ipcidr.is_empty());
        assert!(ff.domain.is_empty());
    }

    #[test]
    fn unknown_fields_are_silently_captured() {
        let yaml = r#"
enable: true
some-future-field: "value"
another-new-thing: 42
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enable);
        // Unknown fields go into extra
        assert!(config.extra.contains_key("some-future-field"));
        assert!(config.extra.contains_key("another-new-thing"));
    }
}
