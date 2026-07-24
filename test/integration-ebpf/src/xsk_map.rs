#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::XskMap as BtfXskMap,
    macros::{btf_map, map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

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
