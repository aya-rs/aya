#![no_std]
#![no_main]

use aya_ebpf::{bindings::tcx_action_base::TCX_NEXT, macros::classifier, programs::TcContext};

#[classifier]
pub fn tcx_next(_ctx: TcContext) -> i32 {
    TCX_NEXT
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
