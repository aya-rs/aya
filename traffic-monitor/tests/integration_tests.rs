use std::{
    net::Ipv4Addr,
    path::PathBuf,
    time::Duration,
};
use tempfile::NamedTempFile;
use traffic_monitor::{
    config::TrafficMonitorConfig,
    event_handler::{EventHandler, TrafficEvent},
    ip_utils::{ip_in_cidr, parse_cidr},
};

#[test]
fn test_config_loading() {
    let config = TrafficMonitorConfig {
        permitted_cidrs: vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
        ],
    };

    let temp_file = NamedTempFile::new().unwrap();
    config.save(temp_file.path()).unwrap();
    
    let loaded_config = TrafficMonitorConfig::load(temp_file.path()).unwrap();
    assert_eq!(config.permitted_cidrs, loaded_config.permitted_cidrs);
}

#[test]
fn test_cidr_parsing_and_matching() {
    // Test valid CIDR parsing
    let (network, prefix) = parse_cidr("192.168.1.0/24").unwrap();
    assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
    assert_eq!(prefix, 24);

    // Test IP matching
    assert!(ip_in_cidr(Ipv4Addr::new(192, 168, 1, 100), network, prefix));
    assert!(!ip_in_cidr(Ipv4Addr::new(192, 168, 2, 100), network, prefix));
    
    // Test edge cases
    let (network, prefix) = parse_cidr("0.0.0.0/0").unwrap();
    assert!(ip_in_cidr(Ipv4Addr::new(8, 8, 8, 8), network, prefix)); // Should match any IP
    
    let (network, prefix) = parse_cidr("127.0.0.1/32").unwrap();
    assert!(ip_in_cidr(Ipv4Addr::new(127, 0, 0, 1), network, prefix));
    assert!(!ip_in_cidr(Ipv4Addr::new(127, 0, 0, 2), network, prefix));
}

#[test]
fn test_event_handler() {
    let mut handler = EventHandler::new();
    
    // Create test events
    let events = vec![
        TrafficEvent {
            src_ip: u32::from(Ipv4Addr::new(8, 8, 8, 8)).to_be(),
            dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 100)).to_be(),
            src_port: 53,
            dst_port: 12345,
            protocol: 17, // UDP
            packet_size: 64,
            action: 0,
        },
        TrafficEvent {
            src_ip: u32::from(Ipv4Addr::new(1, 1, 1, 1)).to_be(),
            dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 100)).to_be(),
            src_port: 443,
            dst_port: 54321,
            protocol: 6, // TCP
            packet_size: 1500,
            action: 1, // Dropped
        },
    ];

    // Process events
    for event in events {
        handler.handle_event(event);
    }

    // Check statistics
    let stats = handler.get_stats();
    assert_eq!(stats.len(), 2); // Two unique source IPs
    
    // Check that we have stats for both IPs
    let google_dns_key = u32::from(Ipv4Addr::new(8, 8, 8, 8)).to_be();
    let cloudflare_dns_key = u32::from(Ipv4Addr::new(1, 1, 1, 1)).to_be();
    
    assert!(stats.contains_key(&google_dns_key));
    assert!(stats.contains_key(&cloudflare_dns_key));
    
    // Check protocol stats
    let google_stats = &stats[&google_dns_key];
    assert_eq!(google_stats.count, 1);
    assert_eq!(google_stats.total_bytes, 64);
    assert_eq!(google_stats.protocols.get(&17), Some(&1)); // UDP

    let cloudflare_stats = &stats[&cloudflare_dns_key];
    assert_eq!(cloudflare_stats.count, 1);
    assert_eq!(cloudflare_stats.total_bytes, 1500);
    assert_eq!(cloudflare_stats.protocols.get(&6), Some(&1)); // TCP
}

#[test]
fn test_comprehensive_cidr_scenarios() {
    let test_cases = vec![
        // (CIDR, test_ip, should_match)
        ("192.168.0.0/16", "192.168.1.1", true),
        ("192.168.0.0/16", "192.169.1.1", false),
        ("10.0.0.0/8", "10.255.255.255", true),
        ("10.0.0.0/8", "11.0.0.1", false),
        ("172.16.0.0/12", "172.16.0.1", true),
        ("172.16.0.0/12", "172.32.0.1", false),
        ("127.0.0.0/8", "127.0.0.1", true),
        ("127.0.0.0/8", "128.0.0.1", false),
        ("0.0.0.0/0", "8.8.8.8", true), // Should match any IP
        ("192.168.1.100/32", "192.168.1.100", true),
        ("192.168.1.100/32", "192.168.1.101", false),
    ];

    for (cidr_str, ip_str, expected) in test_cases {
        let (network, prefix) = parse_cidr(cidr_str).unwrap();
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let result = ip_in_cidr(ip, network, prefix);
        
        assert_eq!(
            result, expected,
            "CIDR: {}, IP: {}, expected: {}, got: {}",
            cidr_str, ip_str, expected, result
        );
    }
}

#[test]
fn test_invalid_cidr_formats() {
    let invalid_cidrs = vec![
        "192.168.1.0",        // Missing prefix
        "192.168.1.0/",       // Empty prefix
        "192.168.1.0/33",     // Invalid prefix (> 32)
        "256.1.1.1/24",       // Invalid IP
        "192.168.1.0/abc",    // Non-numeric prefix
        "not.an.ip/24",       // Invalid IP format
        "",                   // Empty string
        "/24",                // Missing IP
    ];

    for invalid_cidr in invalid_cidrs {
        assert!(
            parse_cidr(invalid_cidr).is_err(),
            "Should have failed to parse: {}",
            invalid_cidr
        );
    }
}

#[test]
fn test_event_statistics_aggregation() {
    let mut handler = EventHandler::new();
    let src_ip = u32::from(Ipv4Addr::new(8, 8, 8, 8)).to_be();
    
    // Send multiple events from the same IP
    for i in 0..5 {
        let event = TrafficEvent {
            src_ip,
            dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 100)).to_be(),
            src_port: 1000 + i,
            dst_port: 80,
            protocol: if i % 2 == 0 { 6 } else { 17 }, // Alternate TCP/UDP
            packet_size: 100 + (i as u16) * 10,
            action: 0,
        };
        handler.handle_event(event);
    }

    let stats = handler.get_stats();
    let ip_stats = &stats[&src_ip];
    
    assert_eq!(ip_stats.count, 5);
    assert_eq!(ip_stats.total_bytes, 100 + 110 + 120 + 130 + 140); // Sum of packet sizes
    assert_eq!(ip_stats.protocols.len(), 2); // TCP and UDP
    assert_eq!(ip_stats.protocols.get(&6), Some(&3)); // 3 TCP packets
    assert_eq!(ip_stats.protocols.get(&17), Some(&2)); // 2 UDP packets
}

#[test]
fn test_default_config() {
    let config = TrafficMonitorConfig::default();
    
    // Should include common private networks
    assert!(config.permitted_cidrs.contains(&"127.0.0.0/8".to_string()));
    assert!(config.permitted_cidrs.contains(&"10.0.0.0/8".to_string()));
    assert!(config.permitted_cidrs.contains(&"172.16.0.0/12".to_string()));
    assert!(config.permitted_cidrs.contains(&"192.168.0.0/16".to_string()));
    
    // Test that these ranges work correctly
    for cidr_str in &config.permitted_cidrs {
        let (network, prefix) = parse_cidr(cidr_str).unwrap();
        
        // Test some IPs that should be in these ranges
        match cidr_str.as_str() {
            "127.0.0.0/8" => {
                assert!(ip_in_cidr(Ipv4Addr::new(127, 0, 0, 1), network, prefix));
            }
            "10.0.0.0/8" => {
                assert!(ip_in_cidr(Ipv4Addr::new(10, 0, 0, 1), network, prefix));
            }
            "172.16.0.0/12" => {
                assert!(ip_in_cidr(Ipv4Addr::new(172, 16, 0, 1), network, prefix));
            }
            "192.168.0.0/16" => {
                assert!(ip_in_cidr(Ipv4Addr::new(192, 168, 1, 1), network, prefix));
            }
            _ => {}
        }
    }
}