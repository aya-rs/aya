#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
#[cfg(not(test))]
extern crate ebpf_panic;

#[xdp]
const fn ihaveaverylongname(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}
