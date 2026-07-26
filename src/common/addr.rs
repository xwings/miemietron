use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Address represents a network destination - either a domain name or IP address with port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Address {
    Domain(String, u16),
    Ip(SocketAddr),
}

impl Address {
    pub fn domain(host: &str, port: u16) -> Self {
        Address::Domain(host.to_string(), port)
    }

    pub fn ip(addr: SocketAddr) -> Self {
        Address::Ip(addr)
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::Domain(_, port) => *port,
            Address::Ip(addr) => addr.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Address::Domain(host, _) => host.clone(),
            Address::Ip(addr) => addr.ip().to_string(),
        }
    }

    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self {
            Address::Domain(_, _) => None,
            Address::Ip(addr) => Some(addr.ip()),
        }
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Address::Domain(_, _))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Domain(host, port) => write!(f, "{host}:{port}"),
            Address::Ip(addr) => write!(f, "{addr}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Ip(addr)
    }
}

/// SOCKS5 address types (RFC 1928 section 5). mihomo:
/// `transport/socks5/socks5.go:36-38`.
pub const SOCKS5_ATYP_IPV4: u8 = 0x01;
pub const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// VMess/VLESS address types. Distinct numbering from SOCKS5 — domain is 2 and
/// IPv6 is 3. mihomo: `transport/vmess/conn.go`, `transport/vless/conn.go`.
pub const VMESS_ATYP_IPV4: u8 = 0x01;
pub const VMESS_ATYP_DOMAIN: u8 = 0x02;
pub const VMESS_ATYP_IPV6: u8 = 0x03;

/// Encode an address in SOCKS5 framing — `ATYP · ADDR · PORT` — into `buf`.
///
/// mihomo compat: `adapter/outbound/util.go serializesSocksAddr`. Used by
/// SOCKS5 itself, Shadowsocks/SSR, Trojan, and anytls. The ATYP numbering is
/// SOCKS5's (1/3/4) and differs from VMess/VLESS's (1/2/3) — mixing them up
/// makes a compliant server read a domain target as IPv6.
pub fn encode_socks5_into(addr: &Address, buf: &mut Vec<u8>) {
    match addr {
        Address::Ip(sockaddr) => match sockaddr.ip() {
            IpAddr::V4(ipv4) => {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                buf.push(SOCKS5_ATYP_IPV6);
                buf.extend_from_slice(&ipv6.octets());
            }
        },
        Address::Domain(domain, _) => {
            buf.push(SOCKS5_ATYP_DOMAIN);
            let domain_bytes = domain.as_bytes();
            buf.push(domain_bytes.len() as u8);
            buf.extend_from_slice(domain_bytes);
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Encode an address in SOCKS5 framing into a fresh, exactly-sized buffer.
pub fn encode_socks5(addr: &Address) -> Vec<u8> {
    let mut buf = Vec::with_capacity(socks5_encoded_len(addr));
    encode_socks5_into(addr, &mut buf);
    buf
}

/// Encode an address in VMess/VLESS framing — `PORT · ATYP · ADDR` — into `buf`.
///
/// mihomo compat: `transport/vless/conn.go` writes
/// `command · BigEndian(port) · addrType · addr` — the port comes BEFORE the
/// address type, unlike the SOCKS5 order. Getting this wrong makes the server
/// read the address bytes as the port and hang.
pub fn encode_vmess_into(addr: &Address, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&addr.port().to_be_bytes());
    match addr {
        Address::Ip(sockaddr) => match sockaddr.ip() {
            IpAddr::V4(ipv4) => {
                buf.push(VMESS_ATYP_IPV4);
                buf.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                buf.push(VMESS_ATYP_IPV6);
                buf.extend_from_slice(&ipv6.octets());
            }
        },
        Address::Domain(domain, _) => {
            buf.push(VMESS_ATYP_DOMAIN);
            let domain_bytes = domain.as_bytes();
            buf.push(domain_bytes.len() as u8);
            buf.extend_from_slice(domain_bytes);
        }
    }
}

/// Encode an address in VMess/VLESS framing into a fresh, exactly-sized buffer.
pub fn encode_vmess(addr: &Address) -> Vec<u8> {
    let mut buf = Vec::with_capacity(socks5_encoded_len(addr));
    encode_vmess_into(addr, &mut buf);
    buf
}

/// Encoded byte length — identical for both framings (they differ only in
/// field order and the ATYP value).
fn socks5_encoded_len(addr: &Address) -> usize {
    match addr {
        // atyp + 4 + port
        Address::Ip(sa) if sa.is_ipv4() => 7,
        // atyp + 16 + port
        Address::Ip(_) => 19,
        // atyp + len + domain + port
        Address::Domain(d, _) => 4 + d.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn create_domain_variant() {
        let addr = Address::domain("example.com", 443);
        assert!(matches!(addr, Address::Domain(ref h, 443) if h == "example.com"));
    }

    #[test]
    fn create_ip_variant() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        let addr = Address::ip(sock);
        assert!(matches!(addr, Address::Ip(s) if s.port() == 8080));
    }

    #[test]
    fn port_domain() {
        let addr = Address::domain("example.com", 9090);
        assert_eq!(addr.port(), 9090);
    }

    #[test]
    fn port_ip() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000));
        let addr = Address::ip(sock);
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn host_domain() {
        let addr = Address::domain("foo.bar", 80);
        assert_eq!(addr.host(), "foo.bar");
    }

    #[test]
    fn host_ip() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80));
        let addr = Address::ip(sock);
        assert_eq!(addr.host(), "10.0.0.1");
    }

    #[test]
    fn ip_addr_returns_some_for_ip() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 443));
        let addr = Address::ip(sock);
        assert_eq!(
            addr.ip_addr(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn ip_addr_returns_none_for_domain() {
        let addr = Address::domain("example.com", 443);
        assert_eq!(addr.ip_addr(), None);
    }

    #[test]
    fn is_domain_true() {
        let addr = Address::domain("example.com", 80);
        assert!(addr.is_domain());
    }

    #[test]
    fn is_domain_false() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80));
        let addr = Address::ip(sock);
        assert!(!addr.is_domain());
    }

    #[test]
    fn display_domain() {
        let addr = Address::domain("example.com", 443);
        assert_eq!(format!("{addr}"), "example.com:443");
    }

    #[test]
    fn display_ipv4() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80));
        let addr = Address::ip(sock);
        assert_eq!(format!("{addr}"), "1.2.3.4:80");
    }

    #[test]
    fn display_ipv6() {
        let sock = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        let addr = Address::ip(sock);
        assert_eq!(format!("{addr}"), "[::1]:443");
    }

    #[test]
    fn from_socket_addr() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        let addr: Address = sock.into();
        assert_eq!(addr, Address::Ip(sock));
    }

    // --- SOCKS5 framing (adapter/outbound/util.go serializesSocksAddr) ---

    #[test]
    fn encode_socks5_ipv4() {
        let addr = Address::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            443,
        )));
        assert_eq!(encode_socks5(&addr), vec![0x01, 10, 0, 0, 1, 0x01, 0xbb]);
    }

    #[test]
    fn encode_socks5_ipv6() {
        let addr = Address::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            80,
            0,
            0,
        )));
        let encoded = encode_socks5(&addr);
        // socks5.AtypIPv6 == 4, NOT 3 (that is VMess's IPv6 tag).
        assert_eq!(encoded[0], 0x04);
        assert_eq!(&encoded[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&encoded[17..19], &80u16.to_be_bytes());
        assert_eq!(encoded.len(), 19);
    }

    #[test]
    fn encode_socks5_domain() {
        let addr = Address::Domain("test.com".to_string(), 8443);
        let encoded = encode_socks5(&addr);
        // socks5.AtypDomainName == 3, NOT 2 (that is VMess's domain tag).
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], 8);
        assert_eq!(&encoded[2..10], b"test.com");
        assert_eq!(&encoded[10..12], &8443u16.to_be_bytes());
        assert_eq!(encoded.len(), 12);
    }

    #[test]
    fn encode_socks5_into_appends() {
        let mut buf = vec![0xff];
        encode_socks5_into(&Address::Domain("a.b".to_string(), 1), &mut buf);
        assert_eq!(buf, vec![0xff, 0x03, 3, b'a', b'.', b'b', 0x00, 0x01]);
    }

    // --- VMess/VLESS framing (transport/vless/conn.go) ---

    #[test]
    fn encode_vmess_ipv4() {
        let addr = Address::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            443,
        )));
        // port first, then atyp.
        assert_eq!(encode_vmess(&addr), vec![0x01, 0xbb, 0x01, 1, 2, 3, 4]);
    }

    #[test]
    fn encode_vmess_ipv6() {
        let addr = Address::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            80,
            0,
            0,
        )));
        let encoded = encode_vmess(&addr);
        assert_eq!(&encoded[0..2], &80u16.to_be_bytes());
        assert_eq!(encoded[2], 0x03); // VMess IPv6 tag is 3.
        assert_eq!(&encoded[3..19], &Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn encode_vmess_domain() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let encoded = encode_vmess(&addr);
        assert_eq!(&encoded[0..2], &443u16.to_be_bytes());
        assert_eq!(encoded[2], 0x02); // VMess domain tag is 2.
        assert_eq!(encoded[3], 11);
        assert_eq!(&encoded[4..15], b"example.com");
        assert_eq!(encoded.len(), 15);
    }

    #[test]
    fn socks5_and_vmess_framings_differ() {
        let addr = Address::Domain("example.com".to_string(), 443);
        assert_ne!(encode_socks5(&addr), encode_vmess(&addr));
    }

    #[test]
    fn encoded_len_matches_capacity() {
        for addr in [
            Address::Domain("a-longer-domain.example".to_string(), 443),
            Address::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))),
            Address::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                1,
                0,
                0,
            ))),
        ] {
            let s = encode_socks5(&addr);
            let v = encode_vmess(&addr);
            assert_eq!(s.len(), s.capacity(), "socks5 capacity for {addr}");
            assert_eq!(v.len(), v.capacity(), "vmess capacity for {addr}");
        }
    }
}
