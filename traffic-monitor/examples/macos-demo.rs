use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};
use traffic_monitor::{
    config::TrafficMonitorConfig,
    event_handler::{EventHandler, TrafficEvent},
    ip_utils::{ip_in_cidr, parse_cidr},
};

/// Demo that simulates the traffic monitor functionality on macOS
/// This shows how the traffic filtering logic works without requiring XDP
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Traffic Monitor Demo for macOS");
    println!("This simulates the eBPF traffic filtering logic without requiring Linux XDP\n");

    // Load configuration
    let config = TrafficMonitorConfig::default();
    println!("📋 Loaded configuration with {} permitted CIDR ranges:", config.permitted_cidrs.len());
    for (i, cidr) in config.permitted_cidrs.iter().enumerate() {
        println!("  {}. {}", i + 1, cidr);
    }
    println!();

    // Parse CIDR ranges
    let mut permitted_ranges = Vec::new();
    for cidr_str in &config.permitted_cidrs {
        if let Ok((network, prefix)) = parse_cidr(cidr_str) {
            permitted_ranges.push((network, prefix, cidr_str.clone()));
            println!("✅ Parsed CIDR: {} -> network={}, prefix={}", cidr_str, network, prefix);
        } else {
            println!("❌ Failed to parse CIDR: {}", cidr_str);
        }
    }
    println!();

    // Initialize event handler
    let mut event_handler = EventHandler::new();

    // Simulate various IP addresses and show how they would be handled
    let test_ips = vec![
        ("127.0.0.1", "Localhost"),
        ("192.168.1.100", "Your local network"),
        ("10.0.0.50", "Private Class A"),
        ("172.16.0.10", "Private Class B"),
        ("8.8.8.8", "Google DNS (PUBLIC)"),
        ("1.1.1.1", "Cloudflare DNS (PUBLIC)"),
        ("52.85.83.228", "Amazon AWS (PUBLIC)"),
        ("140.82.113.4", "GitHub (PUBLIC)"),
        ("192.168.1.242", "Your current IP"),
    ];

    println!("🔍 Testing IP addresses against permitted ranges:\n");

    for (ip_str, description) in &test_ips {
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let mut is_permitted = false;
        let mut matched_cidr = String::new();

        // Check against all CIDR ranges
        for (network, prefix, cidr_str) in &permitted_ranges {
            if ip_in_cidr(ip, *network, *prefix) {
                is_permitted = true;
                matched_cidr = cidr_str.clone();
                break;
            }
        }

        let status = if is_permitted { "✅ PERMITTED" } else { "🚫 NOT PERMITTED" };
        let match_info = if is_permitted {
            format!(" (matches {})", matched_cidr)
        } else {
            String::new()
        };

        println!("  {} - {} - {}{}", ip_str, description, status, match_info);

        // If not permitted, simulate logging the event
        if !is_permitted {
            let event = TrafficEvent {
                src_ip: u32::from(ip).to_be(),
                dst_ip: u32::from(Ipv4Addr::new(192, 168, 1, 242)).to_be(), // Your IP
                src_port: 443,
                dst_port: 12345,
                protocol: 6, // TCP
                packet_size: 1500,
                action: 0, // Log only (would be 1 for drop)
            };
            event_handler.handle_event(event);
        }
    }

    println!("\n📊 Statistics Summary:");
    let stats = event_handler.get_stats();
    if stats.is_empty() {
        println!("  No non-permitted traffic detected");
    } else {
        for (ip_be, ip_stats) in stats {
            let ip = Ipv4Addr::from(u32::from_be(*ip_be));
            println!("  {} - {} packets, {} bytes", ip, ip_stats.count, ip_stats.total_bytes);
        }
    }

    println!("\n🖥️  On a Linux system, this would:");
    println!("  1. Load the eBPF program at the XDP layer");
    println!("  2. Attach to your WiFi interface (en0)");
    println!("  3. Process packets in real-time at line speed");
    println!("  4. Log non-permitted traffic to userspace via ring buffer");
    println!("  5. Optionally drop packets based on configuration");

    println!("\n🐧 To test on Linux:");
    println!("  sudo ./target/release/traffic-monitor -i wlan0 -c configs/default.json");

    Ok(())
}