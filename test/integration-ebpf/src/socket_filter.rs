#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::Array,
    programs::SkBuffContext,
};
use integration_common::socket_filter::{PASS_HITS_INDEX, TRIM_DELTA_BYTES, TRIM_HITS_INDEX};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map(name = "path_hits")]
static PATH_HITS: Array<u64> = Array::with_max_entries(2, 0);

#[inline]
fn record_hit(index: u32) {
    let Some(hit) = PATH_HITS.get_ptr_mut(index) else {
        return;
    };

    unsafe {
        *hit += 1;
    }
}

#[socket_filter]
fn pass_packets(ctx: SkBuffContext) -> i64 {
    record_hit(PASS_HITS_INDEX);
    i64::from(ctx.len())
}

#[socket_filter]
fn trim_packets(ctx: SkBuffContext) -> i64 {
    record_hit(TRIM_HITS_INDEX);
    i64::from(ctx.len().saturating_sub(TRIM_DELTA_BYTES))
}
