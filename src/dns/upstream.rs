use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

use crate::config::DnsConfig;

/// Resolve a domain by querying upstream DNS servers.
pub async fn resolve(domain: &str, config: &DnsConfig) -> Result<IpAddr> {
    // Try nameservers first, then fallback
    let servers = if !config.nameserver.is_empty() {
        &config.nameserver
    } else if !config.default_nameserver.is_empty() {
        &config.default_nameserver
    } else {
        // Hardcoded fallback
        return resolve_udp(domain, "8.8.8.8:53").await;
    };

    for server in servers {
        let result = if server.starts_with("https://") {
            resolve_doh(domain, server).await
        } else if server.starts_with("tls://") {
            // DoT - fallback to UDP for now, DoT in Phase 2
            let addr = server.trim_start_matches("tls://");
            let addr = if addr.contains(':') {
                addr.to_string()
            } else {
                format!("{}:853", addr)
            };
            resolve_udp(domain, &addr.replace(":853", ":53")).await
        } else {
            let addr = if server.contains(':') {
                server.clone()
            } else {
                format!("{}:53", server)
            };
            resolve_udp(domain, &addr).await
        };

        if let Ok(ip) = result {
            return Ok(ip);
        }
    }

    Err(anyhow::anyhow!("all DNS servers failed for {}", domain))
}

/// Resolve via plain UDP DNS.
async fn resolve_udp(domain: &str, server: &str) -> Result<IpAddr> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DNS server address {}: {}", server, e))?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(addr).await?;

    // Build DNS query
    let query = build_dns_query(domain, 1); // Type A = 1
    socket.send(&query).await?;

    let mut buf = vec![0u8; 512];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf));

    let n = timeout.await??;
    let response = &buf[..n];

    parse_dns_response(response)
}

/// Resolve via DNS-over-HTTPS.
async fn resolve_doh(domain: &str, url: &str) -> Result<IpAddr> {
    let query = build_dns_query(domain, 1);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);

    let request_url = format!("{}?dns={}", url, encoded);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let response = client
        .get(&request_url)
        .header("Accept", "application/dns-message")
        .send()
        .await?;

    let body = response.bytes().await?;
    parse_dns_response(&body)
}

use base64::Engine;

/// Build a DNS query packet for the given domain and record type.
fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);

    // Header
    let id: u16 = rand_u16();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
    query.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    query.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    query.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    query.extend_from_slice(&[0x00, 0x00]); // Additional: 0

    // Question
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0); // End of domain

    query.extend_from_slice(&qtype.to_be_bytes()); // Type
    query.extend_from_slice(&[0x00, 0x01]); // Class IN

    query
}

/// Parse a DNS response and extract the first A record IP.
fn parse_dns_response(data: &[u8]) -> Result<IpAddr> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("DNS response too short"));
    }

    let _flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    if ancount == 0 {
        return Err(anyhow::anyhow!("no answers in DNS response"));
    }

    // Skip question section
    let mut pos = 12;
    for _ in 0..qdcount {
        // Skip name
        pos = skip_dns_name(data, pos)?;
        pos += 4; // Skip type + class
    }

    // Parse answer section
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= data.len() {
            // A record
            return Ok(IpAddr::V4(Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            )));
        }

        pos += rdlength;
    }

    Err(anyhow::anyhow!("no A record found in DNS response"))
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= data.len() {
            return Err(anyhow::anyhow!("truncated DNS name"));
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (t.subsec_nanos() ^ t.as_secs() as u32) as u16
}
