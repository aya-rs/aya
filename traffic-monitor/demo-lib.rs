pub mod config;
pub mod event_handler;
pub mod ip_utils;

pub use config::TrafficMonitorConfig;
pub use ip_utils::{format_ip_info, ip_in_cidr, parse_cidr};

// Simplified version of TrafficEvent for demo
#[derive(Debug, Clone)]
pub struct TrafficEvent {
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_size: u16,
    pub action: u8,
}