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

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
const fn test_tracepoint_one(_ctx: TracePointContext) -> u32 {
    0
}
#[tracepoint]
const fn test_tracepoint_two(_ctx: TracePointContext) -> u32 {
    0
}
