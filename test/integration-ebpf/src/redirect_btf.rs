#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{Array, CpuMap, DevMap, DevMapHash, XskMap},
    macros::{btf_map, xdp},
    programs::XdpContext,
};

#[btf_map]
static SOCKS: XskMap<1> = XskMap::new();
#[btf_map]
static DEVS: DevMap<1> = DevMap::new();
#[btf_map]
static DEVS_HASH: DevMapHash<1> = DevMapHash::new();
#[btf_map]
static CPUS: CpuMap<1> = CpuMap::new();

/// Hits of a probe, used to test program chaining through CpuMap/DevMap.
/// The first slot counts how many times the "raw" xdp program got executed, while the second slot
/// counts how many times the map programs got executed.
/// This allows the test harness to assert that a specific step got executed.
#[btf_map]
static HITS: Array<u32, 2> = Array::new();

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
    if let Some(hit) = HITS.get_ptr_mut(index) {
        unsafe { *hit += 1 };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
