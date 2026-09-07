#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
#[cfg(not(test))]
extern crate ebpf_panic;

#[tracepoint]
const fn test_tracepoint_one(_ctx: TracePointContext) -> u32 {
    0
}
#[tracepoint]
const fn test_tracepoint_two(_ctx: TracePointContext) -> u32 {
    0
}
