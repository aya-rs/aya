#![no_std]
#![no_main]
#![expect(internal_features, reason = "atomic_xadd is unstable")]
#![expect(unstable_features, reason = "atomic_xadd is unstable")]
#![feature(core_intrinsics)]

use aya_ebpf::{
    EbpfContext as _, Global, helpers,
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::kprobe::{
    COOKIE_NONE_INDEX, COOKIE_SET_INDEX, COOKIE_UNEXPECTED_INDEX, EXPECTED_COOKIE, HITS_INDEX,
};

#[cfg(not(test))]
extern crate ebpf_panic;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<u32> = Global::new(0);

// Userspace sets this to the address of `schedule`, attached with EXPECTED_COOKIE.
#[unsafe(no_mangle)]
static COOKIE_SET_FUNCTION_IP: Global<u64> = Global::new(0);

// Userspace sets this to the address of `try_to_wake_up`, attached without a cookie.
// bpf_get_attach_cookie must therefore return 0 for hits on this function.
#[unsafe(no_mangle)]
static COOKIE_NONE_FUNCTION_IP: Global<u64> = Global::new(0);

#[map]
static HITS: Array<u64> = Array::with_max_entries(1, 0);

// Count hits with no cookie, hits with EXPECTED_COOKIE, and unexpected hits separately.
// Userspace requires both expected counters to increase and no new unexpected hits.
#[map]
static COOKIE_HITS: Array<u64> = Array::with_max_entries(3, 0);

#[inline(always)]
fn should_count(ctx: &ProbeContext) -> bool {
    ctx.tgid() == TARGET_TGID.load()
}

#[kprobe]
fn test_kprobe_trigger(ctx: ProbeContext) -> u32 {
    if !should_count(&ctx) {
        return 0;
    }

    increment(&HITS, HITS_INDEX)
}

#[kprobe(multi)]
fn test_kprobe_multi_trigger(ctx: ProbeContext) -> u32 {
    if !should_count(&ctx) {
        return 0;
    }

    // Counting cookies alone would miss a swap between the two attachment points.
    // Check each cookie against the function address supplied by userspace.
    let function_ip = unsafe { helpers::bpf_get_func_ip(ctx.as_ptr()) };
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let index = if function_ip == COOKIE_SET_FUNCTION_IP.load() && cookie == EXPECTED_COOKIE {
        COOKIE_SET_INDEX
    } else if function_ip == COOKIE_NONE_FUNCTION_IP.load() && cookie == 0 {
        COOKIE_NONE_INDEX
    } else {
        COOKIE_UNEXPECTED_INDEX
    };

    increment(&COOKIE_HITS, index)
}

#[kprobe]
fn test_kprobe_cookie_trigger(ctx: ProbeContext) -> u32 {
    if !should_count(&ctx) {
        return 0;
    }

    // Legacy and fallback tests distinguish the two attachment points by cookie.
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let index = match cookie {
        0 => COOKIE_NONE_INDEX,
        EXPECTED_COOKIE => COOKIE_SET_INDEX,
        _ => COOKIE_UNEXPECTED_INDEX,
    };

    increment(&COOKIE_HITS, index)
}

#[inline(always)]
fn increment(hits: &Array<u64>, index: u32) -> u32 {
    let Some(hits) = hits.get_ptr_mut(index) else {
        return 0;
    };

    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            hits, 1,
        );
    }

    0
}
