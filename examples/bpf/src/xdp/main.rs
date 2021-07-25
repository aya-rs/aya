#![no_std]
#![no_main]

use aya_bpf::bindings::xdp_action;
use aya_bpf::cty::c_long;
use aya_bpf::macros::{map, xdp};
use aya_bpf::maps::Array;
use aya_bpf::programs::XdpContext;

use bpf::xdp::XdpData;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut xdp_stats_map : Array<XdpData> = Array::with_max_entries(1,0);

#[xdp(name = "xdp_stats")]
pub fn xdp_stats(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_stats(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

unsafe fn try_xdp_stats(_ctx: XdpContext) -> Result<u32, c_long> {
    let data = match xdp_stats_map.get(0) {
        Some(data) => data,
        None => return Err(0)
    };
    let xdp_data = XdpData{
        packet_count: data.packet_count + 1,
    };
    xdp_stats_map.set(0, &xdp_data, 0)?;
    Ok(xdp_action::XDP_PASS)
}