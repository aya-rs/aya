#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
#[cfg(not(test))]
extern crate ebpf_panic;

// Note: the `frags` attribute causes this probe to be incompatible with kernel versions < 5.18.0.
// See https://github.com/torvalds/linux/commit/c2f2cdb.
#[xdp(frags)]
const fn pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}
