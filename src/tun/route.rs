use anyhow::Result;
use tracing::{info, warn};

use crate::config::TunConfig;

/// Set up routing rules to direct traffic through the TUN device.
pub async fn setup_routes(config: &TunConfig) -> Result<()> {
    let table = config.ip_route2_table_index.to_string();
    let dev = &config.device;
    let mark = "0x162";

    run_ip(&["route", "add", "default", "dev", dev, "table", &table]).await?;

    let rule_prio = config.ip_route2_rule_index.to_string();
    run_ip(&[
        "rule", "add", "not", "fwmark", mark, "table", &table, "priority", &rule_prio,
    ])
    .await?;

    let mark_prio = (config.ip_route2_rule_index - 1).to_string();
    run_ip(&[
        "rule", "add", "fwmark", mark, "lookup", "main", "priority", &mark_prio,
    ])
    .await?;

    for exclude in &config.route_exclude_address {
        let _ = run_ip(&[
            "route", "add", exclude, "dev", dev, "table", "main", "metric", "0",
        ])
        .await;
    }

    info!("Routes configured: table={}, mark={}", table, mark);
    Ok(())
}

pub async fn cleanup_routes(config: &TunConfig) -> Result<()> {
    let table = config.ip_route2_table_index.to_string();
    let mark = "0x162";

    let _ = run_ip(&["route", "flush", "table", &table]).await;
    let _ = run_ip(&["rule", "del", "not", "fwmark", mark, "table", &table]).await;
    let _ = run_ip(&["rule", "del", "fwmark", mark, "lookup", "main"]).await;

    info!("Routes cleaned up");
    Ok(())
}

/// Set up packet redirection: try nftables first (OpenWrt 25.02+), fall back to iptables.
pub async fn setup_iptables(
    tun_dev: &str,
    tcp_redir_port: u16,
    udp_tproxy_port: u16,
    mark: &str,
) -> Result<()> {
    // Try nftables first — modern OpenWrt uses nft by default
    if try_setup_nftables(tun_dev, tcp_redir_port, udp_tproxy_port, mark)
        .await
        .is_ok()
    {
        info!("nftables: redirect configured for {}", tun_dev);
        return Ok(());
    }

    // Fallback to iptables-legacy
    warn!("nftables setup failed, trying iptables-legacy...");
    if try_setup_iptables_legacy(tun_dev, tcp_redir_port, udp_tproxy_port, mark)
        .await
        .is_ok()
    {
        info!("iptables-legacy: redirect configured for {}", tun_dev);
        return Ok(());
    }

    // Fallback to plain iptables
    warn!("iptables-legacy not available, trying iptables...");
    setup_iptables_impl("iptables", tun_dev, tcp_redir_port, udp_tproxy_port, mark).await
}

pub async fn cleanup_iptables(tun_dev: &str) -> Result<()> {
    // Try nftables cleanup first
    let _ = cleanup_nftables().await;
    // Also try iptables cleanup (in case iptables was used)
    let _ = cleanup_iptables_impl("iptables-legacy", tun_dev).await;
    let _ = cleanup_iptables_impl("iptables", tun_dev).await;
    info!("Firewall rules cleaned up");
    Ok(())
}

// --- nftables implementation ---

async fn try_setup_nftables(tun_dev: &str, tcp_port: u16, udp_port: u16, mark: &str) -> Result<()> {
    // Check if nft is available
    let check = tokio::process::Command::new("nft")
        .arg("--version")
        .output()
        .await;
    if check.is_err() || !check.unwrap().status.success() {
        return Err(anyhow::anyhow!("nft not available"));
    }

    let ruleset = format!(
        r#"
table inet miemietron {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname != "{tun_dev}" return
        mark {mark} return
        ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} return
        meta l4proto tcp redirect to :{tcp_port}
    }}
    chain prerouting_udp {{
        type filter hook prerouting priority mangle; policy accept;
        iifname != "{tun_dev}" return
        mark {mark} return
        ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} return
        meta l4proto udp tproxy to :{udp_port} meta mark set {mark}
    }}
}}
"#,
    );

    // Delete old table if it exists
    let _ = run_cmd("nft", &["delete", "table", "inet", "miemietron"]).await;

    // Write ruleset to temp file and apply with nft -f
    let tmp_path = "/tmp/miemietron_nft.conf";
    tokio::fs::write(tmp_path, &ruleset).await?;
    let output = tokio::process::Command::new("nft")
        .args(["-f", tmp_path])
        .output()
        .await?;
    let _ = tokio::fs::remove_file(tmp_path).await;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("nft failed: {stderr}"));
    }

    Ok(())
}

async fn cleanup_nftables() -> Result<()> {
    let _ = run_cmd("nft", &["delete", "table", "inet", "miemietron"]).await;
    Ok(())
}

// --- iptables-legacy implementation ---

async fn try_setup_iptables_legacy(
    tun_dev: &str,
    tcp_port: u16,
    udp_port: u16,
    mark: &str,
) -> Result<()> {
    // Check if iptables-legacy exists
    let check = tokio::process::Command::new("iptables-legacy")
        .arg("--version")
        .output()
        .await;
    if check.is_err() || !check.unwrap().status.success() {
        return Err(anyhow::anyhow!("iptables-legacy not available"));
    }
    setup_iptables_impl("iptables-legacy", tun_dev, tcp_port, udp_port, mark).await
}

// --- shared iptables implementation ---

async fn setup_iptables_impl(
    cmd: &str,
    tun_dev: &str,
    tcp_redir_port: u16,
    udp_tproxy_port: u16,
    mark: &str,
) -> Result<()> {
    let tcp_port = tcp_redir_port.to_string();
    let udp_port = udp_tproxy_port.to_string();

    // NAT table: TCP REDIRECT
    let _ = run_cmd(cmd, &["-t", "nat", "-N", "MIEMIETRON"]).await;

    run_cmd(
        cmd,
        &[
            "-t",
            "nat",
            "-A",
            "MIEMIETRON",
            "-m",
            "mark",
            "--mark",
            mark,
            "-j",
            "RETURN",
        ],
    )
    .await?;

    for cidr in PRIVATE_CIDRS {
        run_cmd(
            cmd,
            &["-t", "nat", "-A", "MIEMIETRON", "-d", cidr, "-j", "RETURN"],
        )
        .await?;
    }

    run_cmd(
        cmd,
        &[
            "-t",
            "nat",
            "-A",
            "MIEMIETRON",
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &tcp_port,
        ],
    )
    .await?;

    run_cmd(
        cmd,
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            tun_dev,
            "-j",
            "MIEMIETRON",
        ],
    )
    .await?;

    info!("{}: TCP REDIRECT on {} -> port {}", cmd, tun_dev, tcp_port);

    // Mangle table: UDP TPROXY
    let _ = run_cmd(cmd, &["-t", "mangle", "-N", "MIEMIETRON_UDP"]).await;

    run_cmd(
        cmd,
        &[
            "-t",
            "mangle",
            "-A",
            "MIEMIETRON_UDP",
            "-m",
            "mark",
            "--mark",
            mark,
            "-j",
            "RETURN",
        ],
    )
    .await?;

    for cidr in PRIVATE_CIDRS {
        run_cmd(
            cmd,
            &[
                "-t",
                "mangle",
                "-A",
                "MIEMIETRON_UDP",
                "-d",
                cidr,
                "-j",
                "RETURN",
            ],
        )
        .await?;
    }

    run_cmd(
        cmd,
        &[
            "-t",
            "mangle",
            "-A",
            "MIEMIETRON_UDP",
            "-p",
            "udp",
            "-j",
            "TPROXY",
            "--on-port",
            &udp_port,
            "--tproxy-mark",
            mark,
        ],
    )
    .await?;

    run_cmd(
        cmd,
        &[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            tun_dev,
            "-j",
            "MIEMIETRON_UDP",
        ],
    )
    .await?;

    info!("{}: UDP TPROXY on {} -> port {}", cmd, tun_dev, udp_port);
    Ok(())
}

async fn cleanup_iptables_impl(cmd: &str, tun_dev: &str) -> Result<()> {
    let _ = run_cmd(
        cmd,
        &[
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            tun_dev,
            "-j",
            "MIEMIETRON",
        ],
    )
    .await;
    let _ = run_cmd(
        cmd,
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-i",
            tun_dev,
            "-j",
            "MIEMIETRON_UDP",
        ],
    )
    .await;
    let _ = run_cmd(cmd, &["-t", "nat", "-F", "MIEMIETRON"]).await;
    let _ = run_cmd(cmd, &["-t", "nat", "-X", "MIEMIETRON"]).await;
    let _ = run_cmd(cmd, &["-t", "mangle", "-F", "MIEMIETRON_UDP"]).await;
    let _ = run_cmd(cmd, &["-t", "mangle", "-X", "MIEMIETRON_UDP"]).await;
    Ok(())
}

const PRIVATE_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Detect the default outbound network interface by querying the routing table.
/// Returns the interface name (e.g., "eth0") that routes to the internet.
pub async fn detect_default_interface() -> Option<String> {
    let output = tokio::process::Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output looks like: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0"
    // Extract the word after "dev"
    let mut tokens = stdout.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(|s| s.to_string());
        }
    }
    None
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") && !stderr.contains("No such process") {
            return Err(anyhow::anyhow!("ip {} failed: {}", args.join(" "), stderr));
        }
    }
    Ok(())
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already exists") && !stderr.contains("File exists") {
            return Err(anyhow::anyhow!(
                "{} {} failed: {}",
                cmd,
                args.join(" "),
                stderr
            ));
        }
    }
    Ok(())
}
