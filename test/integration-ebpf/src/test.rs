#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{kprobe, xdp},
    programs::{ProbeContext, XdpContext},
};

#[xdp(name = "test_unload_xdp")]
pub fn pass(ctx: XdpContext) -> u32 {
    match unsafe { try_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_pass(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[kprobe]
// truncated name to match bpftool output
pub fn test_unload_kpr(_ctx: ProbeContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
