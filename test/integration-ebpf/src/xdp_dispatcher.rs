#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
#[cfg(not(test))]
extern crate ebpf_panic;

/// XDP program A - returns XDP_PASS
/// Used for testing the xdp-dispatcher with multiple programs
#[xdp]
fn xdp_dispatcher_a(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

/// XDP program B - returns XDP_PASS
/// Used for testing the xdp-dispatcher with multiple programs
#[xdp]
fn xdp_dispatcher_b(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

/// XDP program C - returns XDP_PASS
/// Used for testing the xdp-dispatcher with multiple programs
#[xdp]
fn xdp_dispatcher_c(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}
