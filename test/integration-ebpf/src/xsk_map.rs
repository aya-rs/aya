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

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::XskMap as BtfXskMap,
    macros::{btf_map, map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(1, 0);

#[btf_map]
static SOCKS_BTF: BtfXskMap<1> = BtfXskMap::new();

#[xdp]
fn redirect_sock(ctx: XdpContext) -> u32 {
    let queue_id = ctx.rx_queue_index();
    if SOCKS.get(queue_id) == Some(queue_id) {
        SOCKS
            .redirect(queue_id, 0)
            .unwrap_or(xdp_action::XDP_ABORTED)
    } else {
        xdp_action::XDP_PASS
    }
}

#[xdp]
fn redirect_sock_btf(ctx: XdpContext) -> u32 {
    let queue_id = ctx.rx_queue_index();
    if SOCKS_BTF.get(queue_id) == Some(queue_id) {
        SOCKS_BTF
            .redirect(queue_id, 0)
            .unwrap_or(xdp_action::XDP_ABORTED)
    } else {
        xdp_action::XDP_PASS
    }
}
