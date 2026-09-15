#![no_std]
#![no_main]
#![expect(internal_features, reason = "atomic_xadd is unstable")]
#![expect(unstable_features, reason = "atomic_xadd is unstable")]
#![feature(core_intrinsics)]
#![allow(
    unused_crate_dependencies,
    reason = "ebpf_panic is only required for non-test eBPF builds; importing it unconditionally would register its panic handler during tests and conflict with std"
)]

#[cfg(not(test))]
extern crate ebpf_panic;

// Required for satisfying unused-crate-dependencies lint
#[rustfmt::skip]
use aya_log_ebpf as _;
#[rustfmt::skip]
use integration_ebpf as _;
#[rustfmt::skip]
use integration_common as _;
#[rustfmt::skip]
use network_types as _;

use aya_ebpf::{
    EbpfContext as _, Global,
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};

const INDEX: u32 = 0;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<u32> = Global::new(0);

#[map]
static HITS: Array<u64> = Array::with_max_entries(1, 0);

#[inline(always)]
fn should_count(ctx: &ProbeContext) -> bool {
    ctx.tgid() == TARGET_TGID.load()
}

#[kprobe]
fn test_kprobe_trigger(ctx: ProbeContext) -> u32 {
    if !should_count(&ctx) {
        return 0;
    }

    let Some(hits) = HITS.get_ptr_mut(INDEX) else {
        return 0;
    };

    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            hits, 1,
        );
    }

    0
}
