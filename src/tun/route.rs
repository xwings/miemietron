use anyhow::Result;
use tracing::info;

use crate::config::TunConfig;

/// Set up routing rules to direct traffic through the TUN device.
pub async fn setup_routes(config: &TunConfig) -> Result<()> {
    let table = config.ip_route2_table_index.to_string();
    let dev = &config.device;
    let mark = "0x162"; // Our routing mark for loop prevention

    // Add default route through TUN in our custom table
    run_ip(&["route", "add", "default", "dev", dev, "table", &table]).await?;

    // Rule: unmarked packets use our TUN table
    let rule_prio = config.ip_route2_rule_index.to_string();
    run_ip(&[
        "rule", "add", "not", "fwmark", mark, "table", &table, "priority", &rule_prio,
    ])
    .await?;

    // Rule: marked packets (our outbound proxy connections) use main table
    let mark_prio = (config.ip_route2_rule_index - 1).to_string();
    run_ip(&[
        "rule", "add", "fwmark", mark, "lookup", "main", "priority", &mark_prio,
    ])
    .await?;

    // Exclude local/private networks
    for exclude in &config.route_exclude_address {
        let _ = run_ip(&[
            "route", "add", exclude, "dev", dev, "table", "main", "metric", "0",
        ])
        .await;
    }

    info!("Routes configured: table={}, mark={}", table, mark);
    Ok(())
}

/// Remove routing rules set up by setup_routes.
pub async fn cleanup_routes(config: &TunConfig) -> Result<()> {
    let table = config.ip_route2_table_index.to_string();
    let mark = "0x162";

    let _ = run_ip(&["route", "flush", "table", &table]).await;
    let _ = run_ip(&["rule", "del", "not", "fwmark", mark, "table", &table]).await;
    let _ = run_ip(&["rule", "del", "fwmark", mark, "lookup", "main"]).await;

    info!("Routes cleaned up");
    Ok(())
}

/// Set up iptables rules to REDIRECT TCP traffic from the TUN device to our
/// local transparent listener, and TPROXY UDP traffic similarly.
///
/// The chain name `MIEMIETRON` is used so we can cleanly remove our rules on
/// shutdown without disturbing other iptables state.
pub async fn setup_iptables(
    tun_dev: &str,
    tcp_redir_port: u16,
    udp_tproxy_port: u16,
    mark: &str,
) -> Result<()> {
    let tcp_port = tcp_redir_port.to_string();
    let udp_port = udp_tproxy_port.to_string();

    // --- NAT table: TCP REDIRECT ---

    // Create our chain in the nat table
    let _ = run_iptables(&["-t", "nat", "-N", "MIEMIETRON"]).await;

    // Skip traffic from our own proxy connections (marked packets)
    run_iptables(&[
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
    ])
    .await?;

    // Skip traffic to local/private ranges to avoid loops
    for cidr in &[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ] {
        run_iptables(&["-t", "nat", "-A", "MIEMIETRON", "-d", cidr, "-j", "RETURN"]).await?;
    }

    // REDIRECT all remaining TCP to our transparent listener
    run_iptables(&[
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
    ])
    .await?;

    // Hook our chain into PREROUTING (traffic arriving on TUN)
    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-i",
        tun_dev,
        "-j",
        "MIEMIETRON",
    ])
    .await?;

    info!("iptables: TCP REDIRECT on {} -> port {}", tun_dev, tcp_port);

    // --- Mangle table: UDP TPROXY ---

    // Create our chain in the mangle table
    let _ = run_iptables(&["-t", "mangle", "-N", "MIEMIETRON_UDP"]).await;

    // Skip marked traffic
    run_iptables(&[
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
    ])
    .await?;

    // Skip local/private
    for cidr in &[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ] {
        run_iptables(&[
            "-t",
            "mangle",
            "-A",
            "MIEMIETRON_UDP",
            "-d",
            cidr,
            "-j",
            "RETURN",
        ])
        .await?;
    }

    // TPROXY UDP to our listener
    run_iptables(&[
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
    ])
    .await?;

    // Hook into PREROUTING
    run_iptables(&[
        "-t",
        "mangle",
        "-A",
        "PREROUTING",
        "-i",
        tun_dev,
        "-j",
        "MIEMIETRON_UDP",
    ])
    .await?;

    info!("iptables: UDP TPROXY on {} -> port {}", tun_dev, udp_port);

    // --- Mark our own outbound connections so they bypass the TUN ---
    // This is handled by the routing mark (0x162) set on proxy sockets.
    // The ip rule we add in setup_routes() ensures marked packets use the
    // main routing table instead of being sent back into the TUN.

    Ok(())
}

/// Remove the iptables rules we added.
pub async fn cleanup_iptables(tun_dev: &str) -> Result<()> {
    // Remove hooks from built-in chains
    let _ = run_iptables(&[
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-i",
        tun_dev,
        "-j",
        "MIEMIETRON",
    ])
    .await;
    let _ = run_iptables(&[
        "-t",
        "mangle",
        "-D",
        "PREROUTING",
        "-i",
        tun_dev,
        "-j",
        "MIEMIETRON_UDP",
    ])
    .await;

    // Flush and delete our custom chains
    let _ = run_iptables(&["-t", "nat", "-F", "MIEMIETRON"]).await;
    let _ = run_iptables(&["-t", "nat", "-X", "MIEMIETRON"]).await;
    let _ = run_iptables(&["-t", "mangle", "-F", "MIEMIETRON_UDP"]).await;
    let _ = run_iptables(&["-t", "mangle", "-X", "MIEMIETRON_UDP"]).await;

    info!("iptables rules cleaned up");
    Ok(())
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already exists" type errors
        if !stderr.contains("File exists") && !stderr.contains("No such process") {
            return Err(anyhow::anyhow!("ip {} failed: {}", args.join(" "), stderr));
        }
    }
    Ok(())
}

async fn run_iptables(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("iptables")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already exists" / "Chain already exists" errors
        if !stderr.contains("already exists")
            && !stderr.contains("File exists")
            && !stderr.contains("No chain/target/match")
        {
            return Err(anyhow::anyhow!(
                "iptables {} failed: {}",
                args.join(" "),
                stderr
            ));
        }
    }
    Ok(())
}
