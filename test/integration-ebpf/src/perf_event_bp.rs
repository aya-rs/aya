#![no_std]
#![no_main]
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
    EbpfContext as _,
    macros::{map, perf_event},
    maps::HashMap,
    programs::PerfEventContext,
};

#[map]
static READERS: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[perf_event]
fn perf_event_bp(ctx: PerfEventContext) -> u32 {
    let tgid = ctx.tgid();
    let addr = unsafe { (*ctx.ctx).addr };
    let _unused: Result<_, _> = READERS.insert(&tgid, &addr, 0);
    0
}
