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

use aya_ebpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};

macro_rules! probe {
    ($name:ident, ($($arg:ident $(= $value:literal)?),*) ) => {
        #[xdp($($arg $(= $value)?),*)]
        const fn $name(_ctx: XdpContext) -> u32 {
            XDP_PASS
        }
    };
}

probe!(xdp_plain, ());
probe!(xdp_frags, (frags));
probe!(xdp_cpumap, (map = "cpumap"));
probe!(xdp_devmap, (map = "devmap"));
probe!(xdp_frags_cpumap, (frags, map = "cpumap"));
probe!(xdp_frags_devmap, (frags, map = "devmap"));
