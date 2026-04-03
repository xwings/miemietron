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
