#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::CpuMap as BtfCpuMap,
    macros::{btf_map, map, xdp},
    maps::{Array, CpuMap},
    programs::XdpContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static CPUS: CpuMap = CpuMap::with_max_entries(1, 0);

#[btf_map]
static CPUS_BTF: BtfCpuMap<1> = BtfCpuMap::new();

/// Counts which probes ran during a chained redirect.
///
/// Slot 0 increments in the entry XDP program; slot 1 increments in the
/// chained program attached via `bpf_cpumap_val::bpf_prog.fd`.
#[map]
static HITS: Array<u32> = Array::with_max_entries(2, 0);

#[xdp]
fn redirect_cpu(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    CPUS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_cpu_btf(_ctx: XdpContext) -> u32 {
    inc_hit(0);
    CPUS_BTF.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp(map = "cpumap")]
fn redirect_cpu_chain(_ctx: XdpContext) -> u32 {
    inc_hit(1);
    xdp_action::XDP_PASS
}

#[inline(always)]
fn inc_hit(index: u32) {
    if let Some(hit) = HITS.get_ptr_mut(index) {
        unsafe { *hit += 1 }
    }
}
