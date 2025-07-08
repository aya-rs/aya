use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::Instant,
};

/// Standalone demo that shows the traffic filtering logic without eBPF dependencies
/// This runs on any platform and demonstrates how the IP filtering would work

// CIDR range structure
#[derive(Debug, Clone)]
struct CidrRange {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl CidrRange {
    fn new(cidr_str: &str) -> Result<Self, String> {
        let parts: Vec<&str> = cidr_str.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: {}", cidr_str));
        }

        let ip: Ipv4Addr = parts[0].parse()
            .map_err(|_| format!("Invalid IP address: {}", parts[0]))?;
        
        let prefix_len: u8 = parts[1].parse()
            .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;
        
        if prefix_len > 32 {
            return Err(format!("Prefix length must be 0-32, got: {}", prefix_len));
        }

        // Calculate the network address
        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let network_u32 = ip_u32 & mask;
        let network_ip = Ipv4Addr::from(network_u32);

        Ok(CidrRange {
            network: network_ip,
            prefix_len,
        })
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix_len == 0 {
            return true; // 0.0.0.0/0 matches everything
        }
        if self.prefix_len > 32 {
            return false;
        }

        let ip_u32 = u32::from(ip);
        let network_u32 = u32::from(self.network);
        
        let mask = if self.prefix_len == 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - self.prefix_len)) - 1)
        };
        
        (ip_u32 & mask) == (network_u32 & mask)
    }
}

// Traffic event structure (mirrors eBPF version)
#[derive(Debug, Clone)]
struct TrafficEvent {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    protocol: &'static str,
    packet_size: u16,
    action: &'static str,
}

// Traffic monitor configuration
struct TrafficMonitor {
    permitted_cidrs: Vec<CidrRange>,
    drop_packets: bool,
    stats: HashMap<Ipv4Addr, (u64, u64)>, // (packet_count, total_bytes)
}

impl TrafficMonitor {
    fn new(cidr_strings: Vec<&str>, drop_packets: bool) -> Result<Self, String> {
        let mut permitted_cidrs = Vec::new();
        for cidr_str in cidr_strings {
            permitted_cidrs.push(CidrRange::new(cidr_str)?);
        }

        Ok(TrafficMonitor {
            permitted_cidrs,
            drop_packets,
            stats: HashMap::new(),
        })
    }

    fn is_permitted(&self, ip: Ipv4Addr) -> bool {
        for cidr in &self.permitted_cidrs {
            if cidr.contains(ip) {
                return true;
            }
        }
        false
    }

    fn process_packet(&mut self, event: TrafficEvent) -> &'static str {
        if self.is_permitted(event.src_ip) {
            "ALLOWED"
        } else {
            // Update statistics
            let entry = self.stats.entry(event.src_ip).or_insert((0, 0));
            entry.0 += 1; // packet count
            entry.1 += event.packet_size as u64; // total bytes

            let action = if self.drop_packets { "DROPPED" } else { "LOGGED" };
            
            println!(
                "[{}] Non-permitted traffic: {}:{} -> {}:{} (proto: {}, size: {} bytes)",
                action, event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                event.protocol, event.packet_size
            );

            action
        }
    }

    fn print_stats(&self) {
        if self.stats.is_empty() {
            println!("📊 No non-permitted traffic detected");
            return;
        }

        println!("\n📊 Non-permitted Traffic Statistics:");
        println!("====================================");
        
        let mut sorted: Vec<_> = self.stats.iter().collect();
        sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0)); // Sort by packet count

        for (ip, (packets, bytes)) in sorted {
            println!("  {} - {} packets, {} bytes", ip, packets, bytes);
        }
        
        let total_packets: u64 = self.stats.values().map(|(p, _)| p).sum();
        let total_bytes: u64 = self.stats.values().map(|(_, b)| b).sum();
        println!("  Total: {} packets, {} bytes from {} unique IPs", 
                total_packets, total_bytes, self.stats.len());
    }
}

fn main() -> Result<(), String> {
    println!("🚀 Traffic Monitor - Standalone Demo");
    println!("=====================================\n");

    // Configuration - default private networks
    let permitted_cidrs = vec![
        "127.0.0.0/8",    // Localhost
        "10.0.0.0/8",     // Private Class A
        "172.16.0.0/12",  // Private Class B  
        "192.168.0.0/16", // Private Class C
    ];

    println!("📋 Configured permitted CIDR ranges:");
    for (i, cidr) in permitted_cidrs.iter().enumerate() {
        println!("  {}. {}", i + 1, cidr);
    }
    println!();

    // Create traffic monitor
    let mut monitor = TrafficMonitor::new(permitted_cidrs, false)?;

    // Simulate various traffic scenarios
    let test_packets = vec![
        TrafficEvent {
            src_ip: "127.0.0.1".parse().unwrap(),
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP",
            packet_size: 1500,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "192.168.1.100".parse().unwrap(),
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 22,
            dst_port: 54321,
            protocol: "TCP", 
            packet_size: 64,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "10.0.0.50".parse().unwrap(),
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 443,
            dst_port: 12345,
            protocol: "TCP",
            packet_size: 1200,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "8.8.8.8".parse().unwrap(), // Google DNS - NOT permitted
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 53,
            dst_port: 32768,
            protocol: "UDP",
            packet_size: 128,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "1.1.1.1".parse().unwrap(), // Cloudflare DNS - NOT permitted
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 53,
            dst_port: 32769,
            protocol: "UDP",
            packet_size: 256,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "52.85.83.228".parse().unwrap(), // Amazon AWS - NOT permitted
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 443,
            dst_port: 12346,
            protocol: "TCP",
            packet_size: 1500,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "140.82.113.4".parse().unwrap(), // GitHub - NOT permitted
            dst_ip: "192.168.1.242".parse().unwrap(), 
            src_port: 22,
            dst_port: 12347,
            protocol: "TCP",
            packet_size: 800,
            action: "TEST",
        },
        TrafficEvent {
            src_ip: "172.16.0.10".parse().unwrap(), // Private Class B - permitted
            dst_ip: "192.168.1.242".parse().unwrap(),
            src_port: 8080,
            dst_port: 12348,
            protocol: "TCP",
            packet_size: 500,
            action: "TEST",
        },
    ];

    println!("🔍 Processing simulated traffic packets:\n");

    for (i, packet) in test_packets.iter().enumerate() {
        let action = monitor.process_packet(packet.clone());
        
        if action == "ALLOWED" {
            println!("[ALLOWED] Permitted traffic: {}:{} -> {}:{} (proto: {}, size: {} bytes)",
                    packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port,
                    packet.protocol, packet.packet_size);
        }
        
        // Add some variety - simulate multiple packets from same IPs
        if i == 3 || i == 4 { // Repeat Google DNS and Cloudflare packets
            for _ in 0..3 {
                let mut repeat_packet = packet.clone();
                repeat_packet.packet_size += 50; // Vary packet size
                monitor.process_packet(repeat_packet);
            }
        }
    }

    monitor.print_stats();

    println!("\n🖥️  On a Linux system with this traffic monitor:");
    println!("1. The eBPF program would run at the XDP layer on your WiFi interface");
    println!("2. It would process packets at line speed (millions of packets per second)");
    println!("3. Only non-permitted traffic would be sent to userspace for logging");
    println!("4. Permitted traffic would pass through with minimal overhead");
    println!("5. With --drop-packets, non-permitted traffic would be dropped in the kernel");

    println!("\n🐧 To run the full version on Linux:");
    println!("sudo ./target/release/traffic-monitor -i en0 -c configs/default.json");

    println!("\n✨ Demo completed successfully!");

    Ok(())
}