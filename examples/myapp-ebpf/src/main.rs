#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};

use core::mem;
use memoffset::offset_of;
use myapp_common::PacketLog;

// ANCHOR: bindings
mod bindings;
use bindings::{ethhdr, iphdr};
// ANCHOR_END: bindings

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

// ANCHOR: map
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);
// ANCHOR_END: map

// ANCHOR: blocklist
#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);
// ANCHOR_END: blocklist

#[xdp(name="myapp")]
pub fn xdp_myapp(ctx: XdpContext) -> u32 {
    match try_xdp_myapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// ANCHOR: ptr_at
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
// ANCHOR_END: ptr_at

// ANCHOR: block_ip
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}
// ANCHOR_END: block_ip

// ANCHOR: try
fn try_xdp_myapp(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let dest = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    // ANCHOR: action
    let action = if block_ip(dest) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    // ANCHOR_END: action

    let log_entry = PacketLog {
        ipv4_address: dest,
        action: action,
    };

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }

    Ok(action)
}
// ANCHOR_END: try

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
