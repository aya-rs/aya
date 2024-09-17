#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::tcx_action_base::{TCX_NEXT, TCX_PASS},
    macros::classifier,
    programs::TcContext,
};

#[classifier]
pub fn tcx_next(ctx: TcContext) -> i32 {
    match try_tcxtest(ctx) {
        Ok(ret) => ret,
        Err(_) => TCX_PASS,
    }
}

fn try_tcxtest(_ctx: TcContext) -> Result<i32, u32> {
    Ok(TCX_NEXT)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
