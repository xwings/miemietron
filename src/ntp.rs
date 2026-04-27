//! Simple NTP client for time synchronization.
//!
//! Sends a single NTP request to the configured server and computes the
//! clock offset. Used for validating system time on routers where NTP
//! may not be configured.

use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// NTP configuration.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct NtpConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_ntp_server")]
    pub server: String,
    #[serde(default = "default_ntp_port")]
    pub port: u16,
    #[serde(default = "default_ntp_interval")]
    pub interval: u64,
    #[serde(default, rename = "write-to-system")]
    pub write_to_system: bool,
}

fn default_ntp_server() -> String {
    "pool.ntp.org".to_string()
}
fn default_ntp_port() -> u16 {
    123
}
fn default_ntp_interval() -> u64 {
    30
}

const NTP_EPOCH_OFFSET: u64 = 2_208_988_800; // Seconds between 1900 and 1970

/// Query an NTP server and return the clock offset in milliseconds.
pub async fn query_ntp(server: &str, port: u16) -> Result<i64> {
    let addr_str = format!("{server}:{port}");

    // Resolve the NTP server
    let addr: SocketAddr = tokio::net::lookup_host(&addr_str)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve NTP server: {server}"))?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Build NTP request packet (48 bytes)
    // LI=0, VN=4, Mode=3 (client) → first byte = 0x23
    let mut packet = [0u8; 48];
    packet[0] = 0x23;

    let t1 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    socket.send_to(&packet, addr).await?;

    // Wait for response with timeout
    let mut buf = [0u8; 48];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("NTP timeout"))??;

    let t4 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    if n < 48 {
        return Err(anyhow::anyhow!("NTP response too short: {n} bytes"));
    }

    // Extract transmit timestamp (bytes 40-47)
    let secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as u64;
    let frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]) as u64;

    let ntp_time_secs = secs.saturating_sub(NTP_EPOCH_OFFSET);
    let ntp_time_ms = ntp_time_secs * 1000 + (frac * 1000 / (1u64 << 32));

    let t1_ms = t1.as_millis() as i64;
    let t4_ms = t4.as_millis() as i64;
    let server_ms = ntp_time_ms as i64;

    // Simplified offset: server_time - ((t1 + t4) / 2)
    let offset = server_ms - (t1_ms + t4_ms) / 2;

    Ok(offset)
}

/// Run periodic NTP sync checks.
pub async fn run_ntp(config: &NtpConfig) {
    if !config.enable {
        return;
    }

    info!(
        "NTP sync started (server: {}:{})",
        config.server, config.port
    );

    let mut interval = tokio::time::interval(Duration::from_secs(config.interval.max(10)));

    loop {
        interval.tick().await;

        match query_ntp(&config.server, config.port).await {
            Ok(offset_ms) => {
                if offset_ms.abs() > 5000 {
                    warn!(
                        "NTP: system clock offset is {}ms (server: {})",
                        offset_ms, config.server
                    );
                } else {
                    debug!("NTP: clock offset {}ms", offset_ms);
                }
            }
            Err(e) => {
                debug!("NTP query failed: {}", e);
            }
        }
    }
}
