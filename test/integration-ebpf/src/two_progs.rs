// Two programs in the same ELF section

#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn test_tracepoint_one(_ctx: TracePointContext) -> u32 {
    0
}
#[tracepoint]
pub fn test_tracepoint_two(_ctx: TracePointContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
