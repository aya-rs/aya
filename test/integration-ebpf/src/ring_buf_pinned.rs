#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static RING_BUF: RingBuf = RingBuf::pinned(0, 0);

#[uprobe]
pub fn ring_buf_test(ctx: ProbeContext) {
    // Write the first argument to the function back out to RING_BUF if it is even,
    // otherwise increment the counter in REJECTED. This exercises discarding data.
    let arg: u64 = match ctx.arg(0) {
        Some(arg) => arg,
        None => return,
    };
    if arg % 2 == 0 {
        let _: Result<(), i64> = RING_BUF.output(&arg, 0);
    }
}
