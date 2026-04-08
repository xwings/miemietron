pub mod dns;
pub mod proxy;
pub mod rules;
pub mod tun;

/// Deserialize a u16 that might be a quoted string (e.g. `port: "7890"`).
fn deserialize_flex_u16<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct FlexU16;
    impl<'de> de::Visitor<'de> for FlexU16 {
        type Value = u16;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a number or string-encoded number")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> { Ok(v as u16) }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> { Ok(v as u16) }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> { Ok(v as u16) }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u16>().map_err(de::Error::custom)
        }
    }
    deserializer.deserialize_any(FlexU16)
}

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

    #[serde(default, deserialize_with = "deserialize_flex_u16")]
    pub port: u16,
    #[serde(default, deserialize_with = "deserialize_flex_u16")]
    pub socks_port: u16,
    #[serde(default, deserialize_with = "deserialize_flex_u16")]
    pub mixed_port: u16,
    #[serde(default, deserialize_with = "deserialize_flex_u16")]
    pub redir_port: u16,
    #[serde(default, deserialize_with = "deserialize_flex_u16")]
    pub tproxy_port: u16,
    #[serde(default)]
    pub allow_lan: bool,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// List of "username:password" pairs for inbound proxy authentication.
    /// When non-empty, SOCKS5 and HTTP proxy inbound connections must authenticate.
    #[serde(default)]
    pub authentication: Vec<String>,

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

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub tcp_concurrent: bool,
    #[serde(default)]
    pub unified_delay: bool,
    #[serde(default = "default_keep_alive_idle")]
    pub keep_alive_idle: u64,
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: u64,
    #[serde(default)]
    pub disable_keep_alive: bool,

    #[serde(default)]
    pub global_client_fingerprint: Option<String>,
    #[serde(default)]
    pub global_ua: Option<String>,

    #[serde(default)]
    pub find_process_mode: Option<String>,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(default)]
    pub tun: TunConfig,

    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,

    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupConfig>,

    #[serde(default)]
    pub rules: Vec<RuleString>,

    #[serde(default, rename = "sub-rules")]
    pub sub_rules: HashMap<String, Vec<RuleString>>,

    #[serde(default, rename = "proxy-providers")]
    pub proxy_providers: HashMap<String, ProxyProviderConfig>,

    #[serde(default, rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,

    #[serde(default)]
    pub hosts: HashMap<String, String>,

    #[serde(default)]
    pub sniffer: Option<SnifferConfig>,

    #[serde(default)]
    pub profile: Option<ProfileConfig>,

    #[serde(default)]
    pub ntp: crate::ntp::NtpConfig,

    #[serde(default, rename = "geox-url")]
    pub geox_url: Option<HashMap<String, String>>,

    #[serde(default)]
    pub geodata_mode: bool,
    #[serde(default)]
    pub geodata_loader: Option<String>,
    #[serde(default)]
    pub geo_auto_update: bool,
    #[serde(default)]
    pub geo_update_interval: Option<u64>,

    #[serde(default)]
    pub tunnels: Vec<serde_yaml::Value>,

    #[serde(default)]
    pub iptables: Option<IptablesConfig>,

    #[serde(default)]
    pub tls: Option<GlobalTlsConfig>,

    #[serde(default)]
    pub experimental: Option<serde_yaml::Value>,

    #[serde(default, rename = "inbound-tfo")]
    pub inbound_tfo: bool,
    #[serde(default, rename = "inbound-mptcp")]
    pub inbound_mptcp: bool,

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
    pub override_destination: bool,
    #[serde(default)]
    pub sniff: HashMap<String, SniffProtocolConfig>,
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

/// Per-protocol sniffing configuration (e.g. TLS, HTTP, QUIC).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SniffProtocolConfig {
    #[serde(default)]
    pub ports: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub override_destination: Option<bool>,
}

impl SnifferConfig {
    /// Check whether sniffing should be attempted for the given destination port.
    /// Returns the effective override-destination flag for that port.
    /// If no `sniff` map is configured, sniff all ports (backwards compat).
    pub fn should_sniff(&self, dst_port: u16) -> Option<bool> {
        if !self.enable {
            return None;
        }
        if self.sniff.is_empty() {
            // No per-protocol config — sniff all ports, use top-level override
            return Some(self.override_destination);
        }
        for pcfg in self.sniff.values() {
            if port_matches(&pcfg.ports, dst_port) {
                let ovr = pcfg.override_destination.unwrap_or(self.override_destination);
                return Some(ovr);
            }
        }
        None // port not in any protocol's list
    }

    /// Check if a domain is in the force-domain list (suffix matching with `+.`).
    pub fn is_force_domain(&self, domain: &str) -> bool {
        domain_matches_list(domain, &self.force_domain)
    }

    /// Check if a domain is in the skip-domain list.
    pub fn is_skip_domain(&self, domain: &str) -> bool {
        domain_matches_list(domain, &self.skip_domain)
    }
}

/// Check if a port matches a list of port specs (numbers or "start-end" ranges).
fn port_matches(specs: &[serde_yaml::Value], port: u16) -> bool {
    for spec in specs {
        match spec {
            serde_yaml::Value::Number(n) => {
                if let Some(p) = n.as_u64() {
                    if p as u16 == port {
                        return true;
                    }
                }
            }
            serde_yaml::Value::String(s) => {
                if let Some((start, end)) = s.split_once('-') {
                    if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>())
                    {
                        if port >= s && port <= e {
                            return true;
                        }
                    }
                } else if let Ok(p) = s.trim().parse::<u16>() {
                    if p == port {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Check if a domain matches any entry in a list (exact, `+.` suffix, `*.` wildcard).
fn domain_matches_list(domain: &str, list: &[String]) -> bool {
    let d = domain.to_lowercase();
    for pattern in list {
        let p = pattern.to_lowercase();
        if let Some(suffix) = p.strip_prefix("+.") {
            if d == suffix || d.ends_with(&format!(".{suffix}")) {
                return true;
            }
        } else if let Some(suffix) = p.strip_prefix("*.") {
            if d.ends_with(&format!(".{suffix}")) {
                return true;
            }
        } else if d == p {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ProfileConfig {
    #[serde(default)]
    pub store_selected: bool,
    #[serde(default)]
    pub store_fake_ip: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct IptablesConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub inbound_interface: Option<String>,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GlobalTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
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
            .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
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
