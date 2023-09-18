#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, CpuMap, DevMap, DevMapHash, XskMap},
    programs::XdpContext,
};

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(1, 0);
#[map]
static DEVS: DevMap = DevMap::with_max_entries(1, 0);
#[map]
static DEVS_HASH: DevMapHash = DevMapHash::with_max_entries(1, 0);
#[map]
static CPUS: CpuMap = CpuMap::with_max_entries(1, 0);

/// Hits of a probe, used to test program chaining through CpuMap/DevMap.
/// The first slot counts how many times the "raw" xdp program got executed, while the second slot
/// counts how many times the map programs got executed.
/// This allows the test harness to assert that a specific step got executed.
#[map]
static mut HITS: Array<u32> = Array::with_max_entries(2, 0);

#[xdp]
pub fn redirect_sock(_ctx: XdpContext) -> u32 {
    SOCKS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
pub fn redirect_dev(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    DEVS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
pub fn redirect_dev_hash(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    DEVS_HASH.redirect(10, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
pub fn redirect_cpu(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    CPUS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp(map = "cpumap")]
pub fn redirect_cpu_chain(_ctx: XdpContext) -> u32 {
    inc_hit(1);
    xdp_action::XDP_PASS
}

#[xdp(map = "devmap")]
pub fn redirect_dev_chain(_ctx: XdpContext) -> u32 {
    inc_hit(1);
    xdp_action::XDP_PASS
}

#[inline(always)]
fn inc_hit(index: u32) {
    if let Some(hit) = unsafe { HITS.get_ptr_mut(index) } {
        unsafe { *hit += 1 };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
