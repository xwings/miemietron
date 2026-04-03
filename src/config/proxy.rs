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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ss_proxy_config() {
        let yaml = r#"
name: "ss-server"
type: ss
server: 1.2.3.4
port: 8388
cipher: 2022-blake3-aes-256-gcm
password: "dGVzdC1rZXktMTIzNDU2Nzg5MGFiY2RlZg=="
udp: true
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.name, "ss-server");
        assert_eq!(config.proxy_type, "ss");
        assert_eq!(config.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(config.port, Some(8388));
        assert_eq!(config.cipher.as_deref(), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(
            config.password.as_deref(),
            Some("dGVzdC1rZXktMTIzNDU2Nzg5MGFiY2RlZg==")
        );
        assert_eq!(config.udp, Some(true));
    }

    #[test]
    fn parse_vless_config_with_reality() {
        let yaml = r#"
name: "vless-reality"
type: vless
server: example.com
port: 443
uuid: "12345678-1234-1234-1234-123456789abc"
flow: xtls-rprx-vision
tls: true
sni: www.microsoft.com
client-fingerprint: chrome
reality-opts:
  public-key: "abc123publickey"
  short-id: "deadbeef"
network: tcp
udp: true
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.name, "vless-reality");
        assert_eq!(config.proxy_type, "vless");
        assert_eq!(config.server.as_deref(), Some("example.com"));
        assert_eq!(config.port, Some(443));
        assert_eq!(
            config.uuid.as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
        assert_eq!(config.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(config.tls, Some(true));
        assert_eq!(config.sni.as_deref(), Some("www.microsoft.com"));
        assert_eq!(config.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(config.network.as_deref(), Some("tcp"));

        let reality = config.reality_opts.as_ref().unwrap();
        assert_eq!(reality.public_key.as_deref(), Some("abc123publickey"));
        assert_eq!(reality.short_id.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn parse_vmess_config_with_alter_id() {
        let yaml = r#"
name: "vmess-server"
type: vmess
server: vmess.example.com
port: 10086
uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
alterId: 0
cipher: auto
tls: true
network: ws
ws-opts:
  path: /vmess-ws
  headers:
    Host: cdn.example.com
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.name, "vmess-server");
        assert_eq!(config.proxy_type, "vmess");
        assert_eq!(config.server.as_deref(), Some("vmess.example.com"));
        assert_eq!(config.port, Some(10086));
        assert_eq!(
            config.uuid.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
        assert_eq!(config.alter_id, Some(0));
        assert_eq!(config.cipher.as_deref(), Some("auto"));
        assert_eq!(config.tls, Some(true));
        assert_eq!(config.network.as_deref(), Some("ws"));

        let ws = config.ws_opts.as_ref().unwrap();
        assert_eq!(ws.path.as_deref(), Some("/vmess-ws"));
        assert_eq!(
            ws.headers.get("Host").map(|s| s.as_str()),
            Some("cdn.example.com")
        );
    }

    #[test]
    fn parse_ssr_config_with_obfs_protocol() {
        let yaml = r#"
name: "ssr-server"
type: ssr
server: ssr.example.com
port: 9999
cipher: aes-256-cfb
password: "secret"
obfs: http_simple
obfs-param: "cdn.example.com"
protocol: auth_aes128_md5
protocol-param: "12345:abcdef"
udp: false
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.name, "ssr-server");
        assert_eq!(config.proxy_type, "ssr");
        assert_eq!(config.server.as_deref(), Some("ssr.example.com"));
        assert_eq!(config.port, Some(9999));
        assert_eq!(config.cipher.as_deref(), Some("aes-256-cfb"));
        assert_eq!(config.password.as_deref(), Some("secret"));
        assert_eq!(config.udp, Some(false));

        // SSR-specific fields end up in the extra map.
        assert_eq!(
            config.extra.get("obfs").and_then(|v| v.as_str()),
            Some("http_simple")
        );
        assert_eq!(
            config.extra.get("obfs-param").and_then(|v| v.as_str()),
            Some("cdn.example.com")
        );
        assert_eq!(
            config.extra.get("protocol").and_then(|v| v.as_str()),
            Some("auth_aes128_md5")
        );
        assert_eq!(
            config.extra.get("protocol-param").and_then(|v| v.as_str()),
            Some("12345:abcdef")
        );
    }

    #[test]
    fn parse_proxy_config_unknown_fields_ignored() {
        let yaml = r#"
name: "test"
type: ss
server: 1.2.3.4
port: 8388
cipher: aes-256-gcm
password: "pass"
some-future-field: "whatever"
another-unknown: 42
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.name, "test");
        // Unknown fields should be in the extra map, not causing parse errors.
        assert!(config.extra.contains_key("some-future-field"));
        assert!(config.extra.contains_key("another-unknown"));
    }

    #[test]
    fn parse_proxy_group_config() {
        let yaml = r#"
name: "Auto"
type: url-test
proxies:
  - proxy-a
  - proxy-b
url: "http://www.gstatic.com/generate_204"
interval: 300
tolerance: 50
"#;
        let config: ProxyGroupConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.name, "Auto");
        assert_eq!(config.group_type, "url-test");
        assert_eq!(config.proxies, vec!["proxy-a", "proxy-b"]);
        assert_eq!(
            config.url.as_deref(),
            Some("http://www.gstatic.com/generate_204")
        );
        assert_eq!(config.interval, Some(300));
        assert_eq!(config.tolerance, Some(50));
    }

    #[test]
    fn parse_ws_opts() {
        let yaml = r#"
path: /ws-path
headers:
  Host: example.com
  User-Agent: test
max-early-data: 2048
early-data-header-name: Sec-WebSocket-Protocol
"#;
        let opts: WsOpts = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(opts.path.as_deref(), Some("/ws-path"));
        assert_eq!(
            opts.headers.get("Host").map(|s| s.as_str()),
            Some("example.com")
        );
        assert_eq!(opts.max_early_data, Some(2048));
        assert_eq!(
            opts.early_data_header_name.as_deref(),
            Some("Sec-WebSocket-Protocol")
        );
    }

    #[test]
    fn parse_reality_opts() {
        let yaml = r#"
public-key: "test-public-key"
short-id: "abcd1234"
"#;
        let opts: RealityOpts = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(opts.public_key.as_deref(), Some("test-public-key"));
        assert_eq!(opts.short_id.as_deref(), Some("abcd1234"));
    }
}
