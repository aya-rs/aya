#![no_std]
#![no_main]
#![allow(
    unused_crate_dependencies,
    reason = "ebpf_panic is only required for non-test eBPF builds; importing it unconditionally would register its panic handler during tests and conflict with std"
)]

#[cfg(not(test))]
extern crate ebpf_panic;

// Required for satisfying unused-crate-dependencies lint
#[rustfmt::skip]
use aya_log_ebpf as _;
#[rustfmt::skip]
use integration_ebpf as _;
#[rustfmt::skip]
use integration_common as _;
#[rustfmt::skip]
use network_types as _;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

// Note: the `frags` attribute causes this probe to be incompatible with kernel versions < 5.18.0.
// See https://github.com/torvalds/linux/commit/c2f2cdb.
#[xdp(frags)]
const fn pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}
