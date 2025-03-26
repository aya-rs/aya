// Two programs in the same ELF section

#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn test_tracepoint_one(_ctx: TracePointContext) -> u32 {
    0
}
#[tracepoint]
pub fn test_tracepoint_two(_ctx: TracePointContext) -> u32 {
    0
}

aya_ebpf::panic_handler!();
