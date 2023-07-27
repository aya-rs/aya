#![no_builtins]
#![no_main]
#![no_std]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp(name = "ihaveaverylongname")]
pub fn ihaveaverylongname(ctx: XdpContext) -> u32 {
    match unsafe { try_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_pass(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
