#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    EbpfContext as _,
    macros::{map, perf_event},
    maps::HashMap,
    programs::PerfEventContext,
};

#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static READERS: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[perf_event]
fn perf_event_bp(ctx: PerfEventContext) -> u32 {
    let tgid = ctx.tgid();
    let addr = unsafe { (*ctx.ctx).addr };
    let _ = READERS.insert(tgid, addr, 0);
    0
}
