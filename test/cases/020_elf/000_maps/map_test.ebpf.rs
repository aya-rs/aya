//! ```cargo
//! [dependencies]
//! aya-bpf = { path = "../../../../bpf/aya-bpf" }
//! ```

#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
    maps::Array,
};

#[map]
static FOO: Array<u32> = Array::<u32>::with_max_entries(10, 0);

#[map(name = "BAR")]
static BAZ: Array<u32> = Array::<u32>::with_max_entries(10, 0);

#[xdp]
pub fn pass(ctx: XdpContext) -> u32 {
    match unsafe { try_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_pass(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
