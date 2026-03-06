#![cfg_attr(target_arch = "bpf", feature(core_intrinsics))]
#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    EbpfContext as _,
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

const INDEX: u32 = 0;

#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static HITS: Array<u64> = Array::with_max_entries(1, 0);

#[inline(always)]
fn should_count(ctx: &ProbeContext) -> bool {
    let Some(target_tgid) = TARGET_TGID.get(INDEX) else {
        return false;
    };
    ctx.tgid() == *target_tgid
}

#[kprobe]
fn test_kprobe_trigger(ctx: ProbeContext) -> u32 {
    if !should_count(&ctx) {
        return 0;
    }

    let Some(hits) = HITS.get_ptr_mut(INDEX) else {
        return 0;
    };

    #[cfg(target_arch = "bpf")]
    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            hits, 1,
        );
    }

    let _: *mut u64 = hits;

    0
}
