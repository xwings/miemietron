pub mod dns;
pub mod proxy;
pub mod rules;
pub mod tun;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub use self::dns::DnsConfig;
pub use self::proxy::{ProxyConfig, ProxyGroupConfig, ProxyProviderConfig};
pub use self::rules::{RuleProviderConfig, RuleString};
pub use self::tun::TunConfig;

/// Top-level configuration, compatible with mihomo config.yaml format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MiemieConfig {
    /// Tunnel mode: rule, global, direct
    #[serde(default = "default_mode")]
    pub mode: String,

    // --- Inbound ports ---
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub socks_port: u16,
    #[serde(default)]
    pub mixed_port: u16,
    #[serde(default)]
    pub redir_port: u16,
    #[serde(default)]
    pub tproxy_port: u16,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    // --- Authentication ---
    /// List of "username:password" pairs for inbound proxy authentication.
    /// When non-empty, SOCKS5 and HTTP proxy inbound connections must authenticate.
    #[serde(default)]
    pub authentication: Vec<String>,

    // --- External controller ---
    #[serde(default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub external_controller_tls: Option<String>,
    #[serde(default)]
    pub external_controller_unix: Option<String>,
    #[serde(default)]
    pub external_controller_cors: Option<CorsConfig>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub external_ui: Option<String>,
    #[serde(default)]
    pub external_ui_url: Option<String>,
    #[serde(default)]
    pub external_ui_name: Option<String>,

    // --- Logging ---
    #[serde(default = "default_log_level")]
    pub log_level: String,

    // --- Network ---
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub tcp_concurrent: bool,
    #[serde(default = "default_keep_alive_idle")]
    pub keep_alive_idle: u64,
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: u64,
    #[serde(default)]
    pub disable_keep_alive: bool,

    // --- Fingerprint ---
    #[serde(default)]
    pub global_client_fingerprint: Option<String>,
    #[serde(default)]
    pub global_ua: Option<String>,

    // --- Find process ---
    #[serde(default)]
    pub find_process_mode: Option<String>,

    // --- DNS ---
    #[serde(default)]
    pub dns: DnsConfig,

    // --- TUN ---
    #[serde(default)]
    pub tun: TunConfig,

    // --- Proxies ---
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,

    // --- Proxy Groups ---
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupConfig>,

    // --- Rules ---
    #[serde(default)]
    pub rules: Vec<RuleString>,

    // --- Providers ---
    #[serde(default, rename = "proxy-providers")]
    pub proxy_providers: HashMap<String, ProxyProviderConfig>,

    #[serde(default, rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,

    // --- Hosts ---
    #[serde(default)]
    pub hosts: HashMap<String, String>,

    // --- Sniffer ---
    #[serde(default)]
    pub sniffer: Option<SnifferConfig>,

    // --- Profile ---
    #[serde(default)]
    pub profile: Option<ProfileConfig>,

    // --- GeoX URLs ---
    #[serde(default, rename = "geox-url")]
    pub geox_url: Option<HashMap<String, String>>,

    // --- Geodata ---
    #[serde(default)]
    pub geodata_mode: bool,
    #[serde(default)]
    pub geodata_loader: Option<String>,
    #[serde(default)]
    pub geo_auto_update: bool,
    #[serde(default)]
    pub geo_update_interval: Option<u64>,

    // Catch-all for unknown fields (forward compat)
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct CorsConfig {
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_private_network: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SnifferConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub force_domain: Vec<String>,
    #[serde(default)]
    pub skip_domain: Vec<String>,
    #[serde(default)]
    pub force_dns_mapping: bool,
    #[serde(default)]
    pub parse_pure_ip: bool,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ProfileConfig {
    #[serde(default)]
    pub store_selected: bool,
    #[serde(default)]
    pub store_fake_ip: bool,
}

impl MiemieConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config {}: {}", path.display(), e))?;
        Self::parse_str(&content)
    }

    /// Parse a config from a YAML string.
    pub fn parse_str(yaml: &str) -> Result<Self> {
        let config: Self = serde_yaml::from_str(yaml)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;
        Ok(config)
    }
}

fn default_mode() -> String {
    "rule".to_string()
}

fn default_bind_address() -> String {
    "*".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_keep_alive_idle() -> u64 {
    600
}

fn default_keep_alive_interval() -> u64 {
    15
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_CONFIG: &str = r#"
mode: rule
mixed-port: 7890
allow-lan: true
bind-address: "*"
log-level: debug
ipv6: false
external-controller: 127.0.0.1:9090
secret: test-secret

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  nameserver:
    - 114.114.114.114
    - 8.8.8.8
  fallback:
    - tls://1.1.1.1:853

tun:
  enable: true
  device: utun0
  stack: gvisor
  auto-route: true
  auto-detect-interface: true

proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret123

  - name: my-vless
    type: vless
    server: 5.6.7.8
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    tls: true

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - my-ss
      - my-vless
      - DIRECT

  - name: Auto
    type: url-test
    proxies:
      - my-ss
      - my-vless
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,facebook,Proxy
  - IP-CIDR,192.168.0.0/16,DIRECT
  - MATCH,Proxy
"#;

    #[test]
    fn parse_full_config() {
        let config: MiemieConfig = serde_yaml::from_str(FULL_CONFIG).unwrap();
        assert_eq!(config.mode, "rule");
        assert_eq!(config.mixed_port, 7890);
        assert!(config.allow_lan);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.secret, Some("test-secret".to_string()));
        assert_eq!(
            config.external_controller,
            Some("127.0.0.1:9090".to_string())
        );
    }

    #[test]
    fn parse_proxies() {
        let config: MiemieConfig = serde_yaml::from_str(FULL_CONFIG).unwrap();
        assert_eq!(config.proxies.len(), 2);

        let ss = &config.proxies[0];
        assert_eq!(ss.name, "my-ss");
        assert_eq!(ss.proxy_type, "ss");
        assert_eq!(ss.server, Some("1.2.3.4".to_string()));
        assert_eq!(ss.port, Some(8388));
        assert_eq!(ss.cipher, Some("aes-256-gcm".to_string()));

        let vless = &config.proxies[1];
        assert_eq!(vless.name, "my-vless");
        assert_eq!(vless.proxy_type, "vless");
        assert_eq!(
            vless.uuid,
            Some("12345678-1234-1234-1234-123456789012".to_string())
        );
        assert_eq!(vless.tls, Some(true));
    }

    #[test]
    fn parse_proxy_groups() {
        let config: MiemieConfig = serde_yaml::from_str(FULL_CONFIG).unwrap();
        assert_eq!(config.proxy_groups.len(), 2);

        let select = &config.proxy_groups[0];
        assert_eq!(select.name, "Proxy");
        assert_eq!(select.group_type, "select");
        assert_eq!(select.proxies, vec!["my-ss", "my-vless", "DIRECT"]);

        let auto = &config.proxy_groups[1];
        assert_eq!(auto.name, "Auto");
        assert_eq!(auto.group_type, "url-test");
        assert_eq!(auto.interval, Some(300));
    }

    #[test]
    fn parse_rules() {
        let config: MiemieConfig = serde_yaml::from_str(FULL_CONFIG).unwrap();
        assert_eq!(config.rules.len(), 4);
        assert_eq!(config.rules[0], "DOMAIN-SUFFIX,google.com,Proxy");
        assert_eq!(config.rules[3], "MATCH,Proxy");
    }

    #[test]
    fn parse_dns_config() {
        let config: MiemieConfig = serde_yaml::from_str(FULL_CONFIG).unwrap();
        assert!(config.dns.enable);
        assert_eq!(config.dns.listen, "0.0.0.0:1053");
        assert_eq!(config.dns.enhanced_mode, "fake-ip");
        assert_eq!(config.dns.fake_ip_range, "198.18.0.0/15");
        assert_eq!(config.dns.nameserver.len(), 2);
        assert_eq!(config.dns.fallback.len(), 1);
    }

    #[test]
    fn parse_tun_config() {
        let config: MiemieConfig = serde_yaml::from_str(FULL_CONFIG).unwrap();
        assert!(config.tun.enable);
        assert_eq!(config.tun.device, "utun0");
        assert_eq!(config.tun.stack, "gvisor");
        assert!(config.tun.auto_route);
        assert!(config.tun.auto_detect_interface);
    }

    #[test]
    fn unknown_fields_silently_ignored() {
        let yaml = r#"
mode: rule
mixed-port: 7890
unknown-future-field: some-value
another-unknown:
  nested: true
"#;
        let config: MiemieConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, "rule");
        assert_eq!(config.mixed_port, 7890);
        // Unknown fields captured in extra
        assert!(config.extra.contains_key("unknown-future-field"));
    }

    #[test]
    fn missing_optional_fields_get_defaults() {
        let yaml = "{}";
        let config: MiemieConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, "rule");
        assert_eq!(config.bind_address, "*");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.keep_alive_idle, 600);
        assert_eq!(config.keep_alive_interval, 15);
        assert!(!config.allow_lan);
        assert_eq!(config.port, 0);
        assert!(config.proxies.is_empty());
        assert!(config.rules.is_empty());
    }
}
