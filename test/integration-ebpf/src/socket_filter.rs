#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::Array,
    programs::SkBuffContext,
};
use integration_common::socket_filter::{
    PASS_HITS_INDEX, PATH_HITS_MAX_ENTRIES, REUSEPORT_FIRST_LISTENER_INDEX,
    REUSEPORT_SECOND_LISTENER_INDEX, REUSEPORT_SELECT_FIRST_HITS_INDEX,
    REUSEPORT_SELECT_SECOND_HITS_INDEX, TRIM_DELTA_BYTES, TRIM_HITS_INDEX,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map(name = "path_hits")]
static PATH_HITS: Array<u64> = Array::with_max_entries(PATH_HITS_MAX_ENTRIES, 0);

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

#[socket_filter]
fn select_first(_ctx: SkBuffContext) -> i64 {
    record_hit(REUSEPORT_SELECT_FIRST_HITS_INDEX);
    // For SO_ATTACH_REUSEPORT_EBPF, the return value selects
    // `reuse->socks[index]`:
    // https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L517-L525
    // The integration test binds `first` before `second`. The kernel initialises
    // the first group member at socks[0] and appends later sockets at
    // socks[num_socks], so index 0 selects `first`:
    // https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L233-L238
    // https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L124-L130
    REUSEPORT_FIRST_LISTENER_INDEX
}

#[socket_filter]
fn select_second(_ctx: SkBuffContext) -> i64 {
    record_hit(REUSEPORT_SELECT_SECOND_HITS_INDEX);
    // `second` is appended after `first` joins the reuseport group, so index 1
    // selects `second`.
    REUSEPORT_SECOND_LISTENER_INDEX
}
