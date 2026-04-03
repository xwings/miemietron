use anyhow::Result;
use std::net::IpAddr;

/// Detect the default outbound network interface.
pub fn detect_outbound_interface() -> Result<String> {
    // Read /proc/net/route to find default gateway interface
    let content = std::fs::read_to_string("/proc/net/route")?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "00000000" {
            return Ok(fields[0].to_string());
        }
    }
    Err(anyhow::anyhow!("no default route found"))
}

/// Get the IP address of a network interface.
pub fn get_interface_ip(iface: &str) -> Result<IpAddr> {
    let addrs = nix::ifaddrs::getifaddrs()?;
    for addr in addrs {
        if addr.interface_name == iface {
            if let Some(address) = addr.address {
                if let Some(sockaddr) = address.as_sockaddr_in() {
                    return Ok(IpAddr::V4(std::net::Ipv4Addr::from(sockaddr.ip())));
                }
            }
        }
    }
    Err(anyhow::anyhow!("no IP found for interface {}", iface))
}
