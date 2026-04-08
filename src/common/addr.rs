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
        assert_eq!(format!("{}", addr), "example.com:443");
    }

    #[test]
    fn display_ipv4() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80));
        let addr = Address::ip(sock);
        assert_eq!(format!("{}", addr), "1.2.3.4:80");
    }

    #[test]
    fn display_ipv6() {
        let sock = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        let addr = Address::ip(sock);
        assert_eq!(format!("{}", addr), "[::1]:443");
    }

    #[test]
    fn from_socket_addr() {
        let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        let addr: Address = sock.into();
        assert_eq!(addr, Address::Ip(sock));
    }
}
