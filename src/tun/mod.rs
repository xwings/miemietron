pub mod device;
pub mod route;

use anyhow::Result;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

use crate::config::TunConfig;
use crate::conn::ConnectionManager;
use crate::dns::DnsResolver;
use device::TunDevice;

/// Main TUN event loop: read packets from TUN, process them, write responses back.
pub async fn run_tun(
    config: TunConfig,
    conn_manager: Arc<ConnectionManager>,
    dns: Arc<DnsResolver>,
) -> Result<()> {
    let tun_dev = TunDevice::open(&config)?;
    info!("TUN device {} opened (MTU {})", config.device, config.mtu);

    if config.auto_route {
        route::setup_routes(&config).await?;
        info!("Auto-route configured");
    }

    let (mut reader, _writer) = tokio::io::split(tun_dev);
    let mut buf = vec![0u8; config.mtu as usize + 64]; // extra space for headers

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                warn!("TUN device closed");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                error!("TUN read error: {}", e);
                continue;
            }
        };

        let packet = &buf[..n];

        // Parse IP version from first nibble
        if packet.is_empty() {
            continue;
        }

        let version = packet[0] >> 4;
        match version {
            4 => {
                if let Err(e) = handle_ipv4_packet(packet, &conn_manager, &dns).await {
                    debug!("IPv4 packet error: {}", e);
                }
            }
            6 => {
                if let Err(e) = handle_ipv6_packet(packet, &conn_manager, &dns).await {
                    debug!("IPv6 packet error: {}", e);
                }
            }
            _ => {
                debug!("Unknown IP version: {}", version);
            }
        }
    }

    if config.auto_route {
        route::cleanup_routes(&config).await?;
    }

    Ok(())
}

async fn handle_ipv4_packet(
    _packet: &[u8],
    _conn_manager: &ConnectionManager,
    _dns: &DnsResolver,
) -> Result<()> {
    // TODO: Parse IPv4 header, extract protocol/src/dst, hand to connection manager
    // This will be filled in during network stack integration
    Ok(())
}

async fn handle_ipv6_packet(
    _packet: &[u8],
    _conn_manager: &ConnectionManager,
    _dns: &DnsResolver,
) -> Result<()> {
    // TODO: Parse IPv6 header, hand to connection manager
    Ok(())
}
