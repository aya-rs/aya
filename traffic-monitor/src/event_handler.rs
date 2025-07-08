use log::{info, warn};
use crate::TrafficEvent;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

// Mirror of the eBPF TrafficEvent structure
#[repr(C)]
pub struct TrafficEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_size: u16,
    pub action: u8, // 0 = allowed, 1 = dropped
}

#[derive(Debug, Clone)]
pub struct EventStats {
    pub count: u64,
    pub total_bytes: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub protocols: HashMap<u8, u64>,
}

impl EventStats {
    fn new() -> Self {
        Self {
            count: 0,
            total_bytes: 0,
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            protocols: HashMap::new(),
        }
    }

    fn update(&mut self, event: &TrafficEvent) {
        self.count += 1;
        self.total_bytes += event.packet_size as u64;
        self.last_seen = Instant::now();
        *self.protocols.entry(event.protocol).or_insert(0) += 1;
    }
}

pub struct EventHandler {
    stats: HashMap<u32, EventStats>, // keyed by source IP
    last_summary: Instant,
    summary_interval: Duration,
}

impl EventHandler {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
            last_summary: Instant::now(),
            summary_interval: Duration::from_secs(60), // Print summary every minute
        }
    }

    pub fn handle_event(&mut self, event: TrafficEvent) {
        let src_ip = Ipv4Addr::from(u32::from_be(event.src_ip));
        let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_ip));
        
        // Update statistics
        let stats = self.stats.entry(event.src_ip).or_insert_with(EventStats::new);
        stats.update(&event);

        // Log the event
        let protocol_name = protocol_to_string(event.protocol);
        let action_str = if event.action == 1 { "DROPPED" } else { "LOGGED" };
        
        if event.src_port != 0 && event.dst_port != 0 {
            info!(
                "[{}] Non-permitted traffic: {}:{} -> {}:{} (proto: {}, size: {} bytes)",
                action_str, src_ip, event.src_port, dst_ip, event.dst_port, 
                protocol_name, event.packet_size
            );
        } else {
            info!(
                "[{}] Non-permitted traffic: {} -> {} (proto: {}, size: {} bytes)",
                action_str, src_ip, dst_ip, protocol_name, event.packet_size
            );
        }

        // Print periodic summary
        if self.last_summary.elapsed() >= self.summary_interval {
            self.print_summary();
            self.last_summary = Instant::now();
        }
    }

    fn print_summary(&self) {
        if self.stats.is_empty() {
            info!("No non-permitted traffic detected in the last minute");
            return;
        }

        info!("=== Traffic Summary (last {} seconds) ===", self.summary_interval.as_secs());
        
        let mut sorted_ips: Vec<_> = self.stats.iter().collect();
        sorted_ips.sort_by(|a, b| b.1.count.cmp(&a.1.count));

        for (ip, stats) in sorted_ips.iter().take(10) { // Top 10 most active IPs
            let src_ip = Ipv4Addr::from(u32::from_be(**ip));
            let duration = stats.last_seen.duration_since(stats.first_seen);
            
            info!(
                "  {}: {} packets, {} bytes, duration: {:.1}s",
                src_ip, stats.count, stats.total_bytes, duration.as_secs_f64()
            );

            // Show protocol breakdown
            for (proto, count) in &stats.protocols {
                info!("    {}: {} packets", protocol_to_string(*proto), count);
            }
        }

        let total_ips = self.stats.len();
        let total_packets: u64 = self.stats.values().map(|s| s.count).sum();
        let total_bytes: u64 = self.stats.values().map(|s| s.total_bytes).sum();
        
        info!(
            "Total: {} unique IPs, {} packets, {} bytes",
            total_ips, total_packets, total_bytes
        );
        info!("=== End Summary ===");
    }

    pub fn get_stats(&self) -> &HashMap<u32, EventStats> {
        &self.stats
    }

    pub fn clear_stats(&mut self) {
        self.stats.clear();
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn protocol_to_string(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        132 => "SCTP",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_stats_update() {
        let mut stats = EventStats::new();
        let event = TrafficEvent {
            src_ip: 0x0100007f, // 127.0.0.1 in network byte order
            dst_ip: 0x0200a8c0, // 192.168.0.2 in network byte order
            src_port: 12345,
            dst_port: 80,
            protocol: 6, // TCP
            packet_size: 1500,
            action: 0,
        };

        stats.update(&event);
        
        assert_eq!(stats.count, 1);
        assert_eq!(stats.total_bytes, 1500);
        assert_eq!(stats.protocols.get(&6), Some(&1));
    }

    #[test]
    fn test_protocol_names() {
        assert_eq!(protocol_to_string(1), "ICMP");
        assert_eq!(protocol_to_string(6), "TCP");
        assert_eq!(protocol_to_string(17), "UDP");
        assert_eq!(protocol_to_string(255), "Unknown");
    }

    #[test]
    fn test_event_handler_basic() {
        let mut handler = EventHandler::new();
        let event = TrafficEvent {
            src_ip: 0x0100007f,
            dst_ip: 0x0200a8c0,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            packet_size: 1500,
            action: 0,
        };

        handler.handle_event(event);
        
        assert_eq!(handler.stats.len(), 1);
        assert!(handler.stats.contains_key(&0x0100007f));
    }
}