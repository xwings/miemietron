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
