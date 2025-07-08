#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC},
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Maximum number of CIDR ranges we can store
const MAX_CIDR_RANGES: u32 = 256;

// Configuration passed from userspace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub drop_packets: u8, // 0 = log only, 1 = log and drop
}

// CIDR range for IPv4
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CidrRange {
    pub network: u32,   // Network address in network byte order
    pub prefix_len: u8, // Prefix length (0-32)
}

// Traffic event to send to userspace
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

// Maps
#[map]
static CONFIG: HashMap<u32, Config> = HashMap::with_max_entries(1, BPF_F_NO_PREALLOC);

#[map]
static PERMITTED_CIDRS: HashMap<u32, CidrRange> = HashMap::with_max_entries(MAX_CIDR_RANGES, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn is_ip_in_cidr(ip: u32, cidr: &CidrRange) -> bool {
    if cidr.prefix_len == 0 {
        return true; // 0.0.0.0/0 matches everything
    }
    if cidr.prefix_len > 32 {
        return false;
    }
    
    let mask = if cidr.prefix_len == 32 {
        0xFFFFFFFF
    } else {
        !((1u32 << (32 - cidr.prefix_len)) - 1)
    };
    
    (ip & mask) == (cidr.network & mask)
}

#[inline(always)]
fn is_permitted_ip(ip: u32) -> bool {
    // Check against all CIDR ranges
    for i in 0..MAX_CIDR_RANGES {
        if let Some(cidr) = unsafe { PERMITTED_CIDRS.get(&i) } {
            if is_ip_in_cidr(ip, cidr) {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn traffic_monitor(ctx: XdpContext) -> u32 {
    match try_traffic_monitor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_traffic_monitor(ctx: XdpContext) -> Result<u32, ()> {
    // Get configuration
    let config = unsafe { CONFIG.get(&0) }.unwrap_or(&Config { drop_packets: 0 });

    // Parse Ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let eth_proto = unsafe { (*ethhdr).ether_type };

    match eth_proto {
        EtherType::Ipv4 => {
            handle_ipv4(&ctx, config)?;
        }
        EtherType::Ipv6 => {
            // For now, we'll pass IPv6 traffic through
            // Could extend to support IPv6 CIDR ranges later
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {
            // Non-IP traffic, pass through
            return Ok(xdp_action::XDP_PASS);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

fn handle_ipv4(ctx: &XdpContext, config: &Config) -> Result<(), ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };
    let protocol = unsafe { (*ipv4hdr).proto };
    let total_len = unsafe { u16::from_be((*ipv4hdr).tot_len) };
    
    // Calculate IP header length
    let ip_hdr_len = (unsafe { (*ipv4hdr).version_ihl() } & 0x0F) as usize * 4;
    
    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + ip_hdr_len)?;
            (
                unsafe { u16::from_be((*tcphdr).source) },
                unsafe { u16::from_be((*tcphdr).dest) },
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + ip_hdr_len)?;
            (
                unsafe { u16::from_be((*udphdr).source) },
                unsafe { u16::from_be((*udphdr).dest) },
            )
        }
        _ => (0, 0), // Other protocols don't have ports
    };

    // Check if source IP is permitted
    let is_permitted = is_permitted_ip(src_ip);
    
    if !is_permitted {
        // Log the event
        let action = if config.drop_packets == 1 { 1 } else { 0 };
        
        let event = TrafficEvent {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: protocol as u8,
            packet_size: total_len,
            action,
        };

        // Send event to userspace
        if let Some(mut entry) = EVENTS.reserve::<TrafficEvent>(0) {
            unsafe {
                *entry.as_mut_ptr() = event;
            }
            entry.submit(0);
        }

        info!(
            ctx,
            "Non-permitted traffic: {}:{} -> {}:{} (proto: {}, size: {}, action: {})",
            u32::from_be(src_ip),
            src_port,
            u32::from_be(dst_ip),
            dst_port,
            protocol as u8,
            total_len,
            if action == 1 { "DROP" } else { "ALLOW" }
        );

        // Drop packet if configured to do so
        if config.drop_packets == 1 {
            return Err(()); // This will cause XDP_DROP
        }
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}