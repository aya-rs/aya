use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

/// Parse a CIDR notation string into network address and prefix length
pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    
    if parts.len() != 2 {
        return Err(anyhow!("Invalid CIDR format: {}", cidr));
    }

    let ip: Ipv4Addr = parts[0].parse()
        .map_err(|_| anyhow!("Invalid IP address: {}", parts[0]))?;
    
    let prefix_len: u8 = parts[1].parse()
        .map_err(|_| anyhow!("Invalid prefix length: {}", parts[1]))?;
    
    if prefix_len > 32 {
        return Err(anyhow!("Prefix length must be 0-32, got: {}", prefix_len));
    }

    // Calculate the network address by applying the subnet mask
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let network_u32 = ip_u32 & mask;
    let network_ip = Ipv4Addr::from(network_u32);

    Ok((network_ip, prefix_len))
}

/// Check if an IP address is within a CIDR range
pub fn ip_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true; // 0.0.0.0/0 matches everything
    }
    if prefix_len > 32 {
        return false;
    }

    let ip_u32 = u32::from(ip);
    let network_u32 = u32::from(network);
    
    let mask = if prefix_len == 32 {
        0xFFFFFFFF
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    
    (ip_u32 & mask) == (network_u32 & mask)
}

/// Convert IP address to human-readable string with additional info
pub fn format_ip_info(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    let class = match octets[0] {
        1..=126 => "Class A",
        128..=191 => "Class B", 
        192..=223 => "Class C",
        224..=239 => "Class D (Multicast)",
        240..=255 => "Class E (Reserved)",
        _ => "Invalid",
    };
    
    let special = if ip.is_private() {
        " (Private)"
    } else if ip.is_loopback() {
        " (Loopback)"
    } else if ip.is_multicast() {
        " (Multicast)"
    } else if ip.is_broadcast() {
        " (Broadcast)"
    } else {
        " (Public)"
    };
    
    format!("{} [{}{}]", ip, class, special)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_valid() {
        let (network, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_network_calculation() {
        // Input IP is not the network address, should be calculated
        let (network, prefix) = parse_cidr("192.168.1.100/24").unwrap();
        assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_invalid_format() {
        assert!(parse_cidr("192.168.1.0").is_err());
        assert!(parse_cidr("192.168.1.0/24/extra").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid_ip() {
        assert!(parse_cidr("256.1.1.1/24").is_err());
        assert!(parse_cidr("invalid.ip/24").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid_prefix() {
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("192.168.1.0/abc").is_err());
    }

    #[test]
    fn test_ip_in_cidr() {
        let network = Ipv4Addr::new(192, 168, 1, 0);
        
        // Test IPs within the range
        assert!(ip_in_cidr(Ipv4Addr::new(192, 168, 1, 1), network, 24));
        assert!(ip_in_cidr(Ipv4Addr::new(192, 168, 1, 100), network, 24));
        assert!(ip_in_cidr(Ipv4Addr::new(192, 168, 1, 255), network, 24));
        
        // Test IPs outside the range
        assert!(!ip_in_cidr(Ipv4Addr::new(192, 168, 2, 1), network, 24));
        assert!(!ip_in_cidr(Ipv4Addr::new(10, 0, 0, 1), network, 24));
    }

    #[test]
    fn test_ip_in_cidr_edge_cases() {
        let network = Ipv4Addr::new(0, 0, 0, 0);
        
        // /0 should match everything
        assert!(ip_in_cidr(Ipv4Addr::new(1, 2, 3, 4), network, 0));
        assert!(ip_in_cidr(Ipv4Addr::new(255, 255, 255, 255), network, 0));
        
        // /32 should match only exact IP
        let exact_ip = Ipv4Addr::new(192, 168, 1, 1);
        assert!(ip_in_cidr(exact_ip, exact_ip, 32));
        assert!(!ip_in_cidr(Ipv4Addr::new(192, 168, 1, 2), exact_ip, 32));
    }

    #[test]
    fn test_format_ip_info() {
        let info = format_ip_info(Ipv4Addr::new(192, 168, 1, 1));
        assert!(info.contains("192.168.1.1"));
        assert!(info.contains("Class C"));
        assert!(info.contains("Private"));

        let info = format_ip_info(Ipv4Addr::new(127, 0, 0, 1));
        assert!(info.contains("127.0.0.1"));
        assert!(info.contains("Class A"));
        assert!(info.contains("Loopback"));
    }
}