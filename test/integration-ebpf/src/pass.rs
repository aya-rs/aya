#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
aya_ebpf::prelude!();

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

// Note: the `frags` attribute causes this probe to be incompatible with kernel versions < 5.18.0.
// See https://github.com/torvalds/linux/commit/c2f2cdb.
#[xdp(frags)]
pub fn pass(ctx: XdpContext) -> u32 {
    match unsafe { try_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_pass(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}
