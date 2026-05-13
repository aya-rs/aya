#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{DevMap as BtfDevMap, DevMapHash as BtfDevMapHash},
    macros::{btf_map, map, xdp},
    maps::{Array, CpuMap, DevMap, DevMapHash, XskMap, xdp::DevMapValue},
    programs::XdpContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(1, 0);
#[map]
static DEVS: DevMap = DevMap::with_max_entries(1, 0);
#[map]
static DEVS_HASH: DevMapHash = DevMapHash::with_max_entries(1, 0);
#[map]
static CPUS: CpuMap = CpuMap::with_max_entries(1, 0);

#[btf_map]
static DEVS_BTF: BtfDevMap<1> = BtfDevMap::new();
#[btf_map]
static DEVS_HASH_BTF: BtfDevMapHash<1> = BtfDevMapHash::new();

/// Hits of a probe, used to test program chaining through CpuMap/DevMap.
/// The first slot counts how many times the "raw" xdp program got executed, while the second slot
/// counts how many times the map programs got executed.
/// This allows the test harness to assert that a specific step got executed.
#[map]
static HITS: Array<u32> = Array::with_max_entries(2, 0);

#[xdp]
fn redirect_sock(ctx: XdpContext) -> u32 {
    let queue_id = ctx.rx_queue_index();
    if SOCKS.get(queue_id) == Some(queue_id) {
        // Queue ID matches, redirect to AF_XDP socket.
        SOCKS
            .redirect(queue_id, 0)
            .unwrap_or(xdp_action::XDP_ABORTED)
    } else {
        // Queue ID did not match, pass packet to kernel network stack.
        xdp_action::XDP_PASS
    }
}

#[xdp]
fn redirect_dev(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    DEVS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_dev_hash(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    DEVS_HASH.redirect(10, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_dev_btf(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    DEVS_BTF.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_dev_hash_btf(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    DEVS_HASH_BTF
        .redirect(10, 0)
        .unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn get_dev(_ctx: XdpContext) -> u32 {
    DEVS.get(0).map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_dev_hash(_ctx: XdpContext) -> u32 {
    DEVS_HASH
        .get(10)
        .map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_dev_btf(_ctx: XdpContext) -> u32 {
    DEVS_BTF
        .get(0)
        .map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_dev_hash_btf(_ctx: XdpContext) -> u32 {
    DEVS_HASH_BTF
        .get(10)
        .map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[inline(always)]
const fn devmap_action(v: DevMapValue) -> u32 {
    if v.prog_id.is_some() && v.if_index != 0 {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    }
}

#[xdp]
fn redirect_cpu(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    CPUS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp(map = "cpumap")]
fn redirect_cpu_chain(_ctx: XdpContext) -> u32 {
    inc_hit(1);
    xdp_action::XDP_PASS
}

#[xdp(map = "devmap")]
fn redirect_dev_chain(_ctx: XdpContext) -> u32 {
    inc_hit(1);
    xdp_action::XDP_PASS
}

#[inline(always)]
fn inc_hit(index: u32) {
    if let Some(hit) = HITS.get_ptr_mut(index) {
        unsafe { *hit += 1 }
    }
}
