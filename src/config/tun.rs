use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TunConfig {
    #[serde(default)]
    pub enable: bool,

    #[serde(default = "default_device")]
    pub device: String,

    #[serde(default = "default_stack")]
    pub stack: String,

    #[serde(default = "default_mtu")]
    pub mtu: u32,

    #[serde(default)]
    pub gso: bool,
    #[serde(default = "default_gso_max_size")]
    pub gso_max_size: u32,

    // Addressing
    #[serde(default = "default_inet4_address")]
    pub inet4_address: Vec<String>,
    #[serde(default)]
    pub inet6_address: Vec<String>,

    // Routing
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub auto_detect_interface: bool,

    #[serde(default)]
    pub route_address: Vec<String>,
    #[serde(default)]
    pub route_exclude_address: Vec<String>,
    #[serde(default)]
    pub inet4_route_address: Vec<String>,
    #[serde(default)]
    pub inet6_route_address: Vec<String>,
    #[serde(default)]
    pub inet4_route_exclude_address: Vec<String>,
    #[serde(default)]
    pub inet6_route_exclude_address: Vec<String>,

    // DNS hijacking
    #[serde(default)]
    pub dns_hijack: Vec<String>,

    // Filtering
    #[serde(default)]
    pub include_interface: Vec<String>,
    #[serde(default)]
    pub exclude_interface: Vec<String>,
    #[serde(default)]
    pub include_uid: Vec<u32>,
    #[serde(default)]
    pub exclude_uid: Vec<u32>,
    #[serde(default)]
    pub include_uid_range: Vec<String>,
    #[serde(default)]
    pub exclude_uid_range: Vec<String>,
    #[serde(default)]
    pub include_package: Vec<String>,
    #[serde(default)]
    pub exclude_package: Vec<String>,
    #[serde(default)]
    pub exclude_src_port: Vec<u16>,
    #[serde(default)]
    pub exclude_dst_port: Vec<u16>,

    // Timeouts
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout: u64,

    // Advanced
    #[serde(default)]
    pub endpoint_independent_nat: bool,
    #[serde(default)]
    pub disable_icmp_forwarding: bool,
    #[serde(default = "default_ip_route2_table_index")]
    pub ip_route2_table_index: u32,
    #[serde(default = "default_ip_route2_rule_index")]
    pub ip_route2_rule_index: u32,

    // Catch-all
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enable: false,
            device: default_device(),
            stack: default_stack(),
            mtu: default_mtu(),
            gso: false,
            gso_max_size: default_gso_max_size(),
            inet4_address: default_inet4_address(),
            inet6_address: vec![],
            auto_route: false,
            auto_detect_interface: false,
            route_address: vec![],
            route_exclude_address: vec![],
            inet4_route_address: vec![],
            inet6_route_address: vec![],
            inet4_route_exclude_address: vec![],
            inet6_route_exclude_address: vec![],
            dns_hijack: vec![],
            include_interface: vec![],
            exclude_interface: vec![],
            include_uid: vec![],
            exclude_uid: vec![],
            include_uid_range: vec![],
            exclude_uid_range: vec![],
            include_package: vec![],
            exclude_package: vec![],
            exclude_src_port: vec![],
            exclude_dst_port: vec![],
            udp_timeout: default_udp_timeout(),
            endpoint_independent_nat: false,
            disable_icmp_forwarding: false,
            ip_route2_table_index: default_ip_route2_table_index(),
            ip_route2_rule_index: default_ip_route2_rule_index(),
            extra: HashMap::new(),
        }
    }
}

fn default_device() -> String {
    "utun".to_string()
}

fn default_stack() -> String {
    "system".to_string()
}

fn default_mtu() -> u32 {
    9000
}

fn default_gso_max_size() -> u32 {
    65536
}

fn default_inet4_address() -> Vec<String> {
    vec!["198.18.0.1/15".to_string()]
}

fn default_udp_timeout() -> u64 {
    300
}

fn default_ip_route2_table_index() -> u32 {
    100
}

fn default_ip_route2_rule_index() -> u32 {
    32765
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tun_config_has_correct_defaults() {
        let yaml = "{}";
        let config: TunConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(!config.enable);
        assert_eq!(config.device, "utun");
        assert_eq!(config.stack, "system");
        assert_eq!(config.mtu, 9000);
        assert!(!config.gso);
        assert_eq!(config.gso_max_size, 65536);
        assert_eq!(config.inet4_address, vec!["198.18.0.1/15"]);
        assert!(config.inet6_address.is_empty());
        assert!(!config.auto_route);
        assert!(!config.auto_detect_interface);
        assert!(config.route_address.is_empty());
        assert!(config.route_exclude_address.is_empty());
        assert!(config.inet4_route_address.is_empty());
        assert!(config.inet6_route_address.is_empty());
        assert!(config.inet4_route_exclude_address.is_empty());
        assert!(config.inet6_route_exclude_address.is_empty());
        assert!(config.dns_hijack.is_empty());
        assert!(config.include_interface.is_empty());
        assert!(config.exclude_interface.is_empty());
        assert!(config.include_uid.is_empty());
        assert!(config.exclude_uid.is_empty());
        assert!(config.include_uid_range.is_empty());
        assert!(config.exclude_uid_range.is_empty());
        assert!(config.include_package.is_empty());
        assert!(config.exclude_package.is_empty());
        assert!(config.exclude_src_port.is_empty());
        assert!(config.exclude_dst_port.is_empty());
        assert_eq!(config.udp_timeout, 300);
        assert!(!config.endpoint_independent_nat);
        assert!(!config.disable_icmp_forwarding);
        assert_eq!(config.ip_route2_table_index, 100);
        assert_eq!(config.ip_route2_rule_index, 32765);
    }

    #[test]
    fn full_tun_config_parses_all_fields() {
        let yaml = r#"
enable: true
device: miemie0
stack: smoltcp
mtu: 1500
gso: true
gso-max-size: 32768
inet4-address:
  - "10.0.0.1/24"
inet6-address:
  - "fc00::1/7"
auto-route: true
auto-detect-interface: true
route-address:
  - "0.0.0.0/0"
  - "::/0"
route-exclude-address:
  - "192.168.0.0/16"
inet4-route-address:
  - "10.0.0.0/8"
inet6-route-address:
  - "fd00::/8"
inet4-route-exclude-address:
  - "172.16.0.0/12"
inet6-route-exclude-address:
  - "fe80::/10"
dns-hijack:
  - "0.0.0.0:53"
  - "198.18.0.2:53"
include-interface:
  - "eth0"
exclude-interface:
  - "lo"
include-uid:
  - 1000
exclude-uid:
  - 0
include-uid-range:
  - "1000-2000"
exclude-uid-range:
  - "0-999"
include-package:
  - "com.example.app"
exclude-package:
  - "com.example.system"
exclude-src-port:
  - 22
exclude-dst-port:
  - 53
udp-timeout: 600
endpoint-independent-nat: true
disable-icmp-forwarding: true
ip-route2-table-index: 200
ip-route2-rule-index: 32000
"#;
        let config: TunConfig = serde_yaml::from_str(yaml).unwrap();

        assert!(config.enable);
        assert_eq!(config.device, "miemie0");
        assert_eq!(config.stack, "smoltcp");
        assert_eq!(config.mtu, 1500);
        assert!(config.gso);
        assert_eq!(config.gso_max_size, 32768);
        assert_eq!(config.inet4_address, vec!["10.0.0.1/24"]);
        assert_eq!(config.inet6_address, vec!["fc00::1/7"]);
        assert!(config.auto_route);
        assert!(config.auto_detect_interface);
        assert_eq!(config.route_address, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(config.route_exclude_address, vec!["192.168.0.0/16"]);
        assert_eq!(config.inet4_route_address, vec!["10.0.0.0/8"]);
        assert_eq!(config.inet6_route_address, vec!["fd00::/8"]);
        assert_eq!(config.inet4_route_exclude_address, vec!["172.16.0.0/12"]);
        assert_eq!(config.inet6_route_exclude_address, vec!["fe80::/10"]);
        assert_eq!(config.dns_hijack, vec!["0.0.0.0:53", "198.18.0.2:53"]);
        assert_eq!(config.include_interface, vec!["eth0"]);
        assert_eq!(config.exclude_interface, vec!["lo"]);
        assert_eq!(config.include_uid, vec![1000]);
        assert_eq!(config.exclude_uid, vec![0]);
        assert_eq!(config.include_uid_range, vec!["1000-2000"]);
        assert_eq!(config.exclude_uid_range, vec!["0-999"]);
        assert_eq!(config.include_package, vec!["com.example.app"]);
        assert_eq!(config.exclude_package, vec!["com.example.system"]);
        assert_eq!(config.exclude_src_port, vec![22]);
        assert_eq!(config.exclude_dst_port, vec![53]);
        assert_eq!(config.udp_timeout, 600);
        assert!(config.endpoint_independent_nat);
        assert!(config.disable_icmp_forwarding);
        assert_eq!(config.ip_route2_table_index, 200);
        assert_eq!(config.ip_route2_rule_index, 32000);
    }

    #[test]
    fn default_trait_matches_serde_defaults() {
        let from_default = TunConfig::default();
        let from_yaml: TunConfig = serde_yaml::from_str("{}").unwrap();

        assert_eq!(from_default.enable, from_yaml.enable);
        assert_eq!(from_default.device, from_yaml.device);
        assert_eq!(from_default.stack, from_yaml.stack);
        assert_eq!(from_default.mtu, from_yaml.mtu);
        assert_eq!(from_default.gso, from_yaml.gso);
        assert_eq!(from_default.gso_max_size, from_yaml.gso_max_size);
        assert_eq!(from_default.inet4_address, from_yaml.inet4_address);
        assert_eq!(from_default.udp_timeout, from_yaml.udp_timeout);
        assert_eq!(
            from_default.ip_route2_table_index,
            from_yaml.ip_route2_table_index
        );
        assert_eq!(
            from_default.ip_route2_rule_index,
            from_yaml.ip_route2_rule_index
        );
    }

    #[test]
    fn unknown_fields_are_silently_captured() {
        let yaml = r#"
enable: true
some-future-field: "value"
"#;
        let config: TunConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enable);
        assert!(config.extra.contains_key("some-future-field"));
    }

    #[test]
    fn partial_config_uses_defaults_for_missing_fields() {
        let yaml = r#"
enable: true
mtu: 1400
"#;
        let config: TunConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enable);
        assert_eq!(config.mtu, 1400);
        // Everything else should be default
        assert_eq!(config.device, "utun");
        assert_eq!(config.stack, "system");
        assert_eq!(config.gso_max_size, 65536);
        assert_eq!(config.udp_timeout, 300);
    }
}
