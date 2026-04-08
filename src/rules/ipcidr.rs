use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// CIDR matcher using a simple sorted prefix list.
/// TODO: Replace with BART (Balanced Routing Table) or LC-Trie for O(1) lookups.
#[allow(dead_code)]
pub struct CidrMatcher {
    v4_entries: Vec<CidrEntry>,
    v6_entries: Vec<CidrEntry>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CidrEntry {
    network: u128, // IP as u128 (works for both v4 and v6)
    mask: u128,
    prefix_len: u8,
    target: String,
}

#[allow(dead_code)]
impl CidrMatcher {
    pub fn new(cidrs: Vec<(String, String)>) -> Self {
        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();

        for (cidr, target) in cidrs {
            if let Some(entry) = parse_cidr_entry(&cidr, &target) {
                if cidr.contains(':') {
                    v6_entries.push(entry);
                } else {
                    v4_entries.push(entry);
                }
            }
        }

        // Sort by prefix length (longest first) for longest-prefix-match
        v4_entries.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        v6_entries.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));

        Self {
            v4_entries,
            v6_entries,
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let (ip_u128, entries) = match ip {
            IpAddr::V4(v4) => {
                let ip_u128 = u32::from(*v4) as u128;
                (ip_u128, &self.v4_entries)
            }
            IpAddr::V6(v6) => {
                let ip_u128 = u128::from(*v6);
                (ip_u128, &self.v6_entries)
            }
        };

        for entry in entries {
            if (ip_u128 & entry.mask) == entry.network {
                return Some(entry.target.clone());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_cidr_matching() {
        let cidrs = vec![
            ("192.168.1.0/24".to_string(), "lan".to_string()),
            ("10.0.0.0/8".to_string(), "private".to_string()),
        ];
        let matcher = CidrMatcher::new(cidrs);

        let ip1: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(matcher.lookup(&ip1), Some("lan".to_string()));

        let ip2: IpAddr = "10.255.0.1".parse().unwrap();
        assert_eq!(matcher.lookup(&ip2), Some("private".to_string()));
    }

    #[test]
    fn ipv6_cidr_matching() {
        let cidrs = vec![
            ("2001:db8::/32".to_string(), "v6-doc".to_string()),
            ("fe80::/10".to_string(), "link-local".to_string()),
        ];
        let matcher = CidrMatcher::new(cidrs);

        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(matcher.lookup(&ip1), Some("v6-doc".to_string()));

        let ip2: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(matcher.lookup(&ip2), Some("link-local".to_string()));
    }

    #[test]
    fn longest_prefix_match() {
        let cidrs = vec![
            ("192.168.0.0/16".to_string(), "broad".to_string()),
            ("192.168.1.0/24".to_string(), "narrow".to_string()),
        ];
        let matcher = CidrMatcher::new(cidrs);

        // 192.168.1.50 matches both, but /24 is longer prefix -> "narrow"
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(matcher.lookup(&ip), Some("narrow".to_string()));

        // 192.168.2.1 matches only /16 -> "broad"
        let ip2: IpAddr = "192.168.2.1".parse().unwrap();
        assert_eq!(matcher.lookup(&ip2), Some("broad".to_string()));
    }

    #[test]
    fn no_match_returns_none() {
        let cidrs = vec![("192.168.1.0/24".to_string(), "lan".to_string())];
        let matcher = CidrMatcher::new(cidrs);

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.lookup(&ip), None);
    }

    #[test]
    fn empty_matcher_returns_none() {
        let matcher = CidrMatcher::new(vec![]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(matcher.lookup(&ip), None);
    }

    #[test]
    fn single_host_cidr() {
        let cidrs = vec![("1.2.3.4/32".to_string(), "single".to_string())];
        let matcher = CidrMatcher::new(cidrs);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(matcher.lookup(&ip), Some("single".to_string()));

        let ip2: IpAddr = "1.2.3.5".parse().unwrap();
        assert_eq!(matcher.lookup(&ip2), None);
    }
}

#[allow(dead_code)]
fn parse_cidr_entry(cidr: &str, target: &str) -> Option<CidrEntry> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix_len: u8 = parts[1].parse().ok()?;

    if let Ok(v4) = parts[0].parse::<Ipv4Addr>() {
        let ip_u128 = u32::from(v4) as u128;
        let mask = if prefix_len == 0 {
            0u128
        } else {
            !((1u128 << (32 - prefix_len)) - 1)
        };
        let network = ip_u128 & mask;
        Some(CidrEntry {
            network,
            mask,
            prefix_len,
            target: target.to_string(),
        })
    } else if let Ok(v6) = parts[0].parse::<Ipv6Addr>() {
        let ip_u128 = u128::from(v6);
        let mask = if prefix_len == 0 {
            0u128
        } else {
            !((1u128 << (128 - prefix_len)) - 1)
        };
        let network = ip_u128 & mask;
        Some(CidrEntry {
            network,
            mask,
            prefix_len,
            target: target.to_string(),
        })
    } else {
        None
    }
}
