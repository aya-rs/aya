#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    EbpfContext as _, Global,
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

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
        *hits += 1;
    }

    0
}
