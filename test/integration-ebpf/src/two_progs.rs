#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
#[cfg(not(test))]
extern crate ebpf_panic;

#[tracepoint]
fn test_tracepoint_one(_ctx: TracePointContext) -> u32 {
    0
}
#[tracepoint]
fn test_tracepoint_two(_ctx: TracePointContext) -> u32 {
    0
}
