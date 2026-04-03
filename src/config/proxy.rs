use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Proxy definition from config. Uses serde flatten to accept all protocol-specific fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyConfig {
    pub name: String,

    #[serde(rename = "type")]
    pub proxy_type: String,

    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,

    // SS fields
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub udp: Option<bool>,
    #[serde(default)]
    pub udp_over_tcp: Option<bool>,
    #[serde(default)]
    pub udp_over_tcp_version: Option<u8>,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<HashMap<String, serde_yaml::Value>>,

    // VMess fields
    #[serde(default, alias = "alterId")]
    pub alter_id: Option<u16>,

    // VLESS fields
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub xudp: Option<bool>,
    #[serde(default)]
    pub packet_addr: Option<bool>,

    // TLS fields
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub servername: Option<String>,
    #[serde(default)]
    pub skip_cert_verify: Option<bool>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,

    // Reality
    #[serde(default)]
    pub reality_opts: Option<RealityOpts>,

    // ECH
    #[serde(default)]
    pub ech_opts: Option<HashMap<String, serde_yaml::Value>>,

    // Transport
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(default)]
    pub h2_opts: Option<H2Opts>,
    #[serde(default)]
    pub http_opts: Option<HashMap<String, serde_yaml::Value>>,

    // SS over Trojan
    #[serde(default)]
    pub ss_opts: Option<HashMap<String, serde_yaml::Value>>,

    // Base options
    #[serde(default)]
    pub tfo: Option<bool>,
    #[serde(default)]
    pub mptcp: Option<bool>,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub ip_version: Option<String>,
    #[serde(default)]
    pub dialer_proxy: Option<String>,

    // Catch-all
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RealityOpts {
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    #[serde(default)]
    pub support_x25519mlkem768: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct WsOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub max_early_data: Option<u32>,
    #[serde(default)]
    pub early_data_header_name: Option<String>,
    #[serde(default)]
    pub v2ray_http_upgrade: Option<bool>,
    #[serde(default)]
    pub v2ray_http_upgrade_fast_open: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOpts {
    #[serde(default)]
    pub grpc_service_name: Option<String>,
    #[serde(default)]
    pub grpc_user_agent: Option<String>,
    #[serde(default)]
    pub ping_interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct H2Opts {
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyGroupConfig {
    pub name: String,

    #[serde(rename = "type")]
    pub group_type: String,

    #[serde(default)]
    pub proxies: Vec<String>,

    #[serde(default, rename = "use")]
    pub use_providers: Vec<String>,

    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub tolerance: Option<u32>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub max_failed_times: Option<u32>,
    #[serde(default)]
    pub lazy: Option<bool>,
    #[serde(default)]
    pub expected_status: Option<String>,

    #[serde(default)]
    pub strategy: Option<String>,

    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub exclude_filter: Option<String>,
    #[serde(default)]
    pub exclude_type: Option<String>,

    #[serde(default)]
    pub disable_udp: Option<bool>,
    #[serde(default)]
    pub hidden: Option<bool>,
    #[serde(default)]
    pub icon: Option<String>,

    #[serde(default)]
    pub include_all: Option<bool>,
    #[serde(default)]
    pub include_all_proxies: Option<bool>,
    #[serde(default)]
    pub include_all_providers: Option<bool>,

    // Catch-all
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyProviderConfig {
    #[serde(rename = "type")]
    pub provider_type: String,

    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,

    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub exclude_filter: Option<String>,
    #[serde(default)]
    pub exclude_type: Option<String>,

    // Catch-all
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
}
