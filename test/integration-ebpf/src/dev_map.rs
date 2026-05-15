#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{DevMap as BtfDevMap, DevMapHash as BtfDevMapHash},
    macros::{btf_map, map, xdp},
    maps::{DevMap, DevMapHash, xdp::DevMapValue},
    programs::XdpContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static DEVS: DevMap = DevMap::with_max_entries(1, 0);
#[map]
static DEVS_HASH: DevMapHash = DevMapHash::with_max_entries(1, 0);

#[btf_map]
static DEVS_BTF: BtfDevMap<1> = BtfDevMap::new();
#[btf_map]
static DEVS_HASH_BTF: BtfDevMapHash<1> = BtfDevMapHash::new();

#[xdp]
fn redirect_dev(_ctx: XdpContext) -> u32 {
    DEVS.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_dev_hash(_ctx: XdpContext) -> u32 {
    DEVS_HASH.redirect(10, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_dev_btf(_ctx: XdpContext) -> u32 {
    DEVS_BTF.redirect(0, 0).unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn redirect_dev_hash_btf(_ctx: XdpContext) -> u32 {
    DEVS_HASH_BTF
        .redirect(10, 0)
        .unwrap_or(xdp_action::XDP_ABORTED)
}

#[xdp]
fn get_dev(_ctx: XdpContext) -> u32 {
    DEVS.get(0).map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_dev_hash(_ctx: XdpContext) -> u32 {
    DEVS_HASH
        .get(10)
        .map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_dev_btf(_ctx: XdpContext) -> u32 {
    DEVS_BTF
        .get(0)
        .map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_dev_hash_btf(_ctx: XdpContext) -> u32 {
    DEVS_HASH_BTF
        .get(10)
        .map_or(xdp_action::XDP_ABORTED, devmap_action)
}

#[xdp]
fn get_ifindex_dev(_ctx: XdpContext) -> u32 {
    DEVS.get_ifindex(0)
        .map_or(xdp_action::XDP_ABORTED, ifindex_action)
}

#[xdp]
fn get_ifindex_dev_hash(_ctx: XdpContext) -> u32 {
    DEVS_HASH
        .get_ifindex(10)
        .map_or(xdp_action::XDP_ABORTED, ifindex_action)
}

#[xdp]
fn get_ifindex_dev_btf(_ctx: XdpContext) -> u32 {
    DEVS_BTF
        .get_ifindex(0)
        .map_or(xdp_action::XDP_ABORTED, ifindex_action)
}

#[xdp]
fn get_ifindex_dev_hash_btf(_ctx: XdpContext) -> u32 {
    DEVS_HASH_BTF
        .get_ifindex(10)
        .map_or(xdp_action::XDP_ABORTED, ifindex_action)
}

#[inline(always)]
const fn ifindex_action(if_index: u32) -> u32 {
    if if_index != 0 {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    }
}

#[inline(always)]
const fn devmap_action(v: DevMapValue) -> u32 {
    if v.prog_id.is_some() && v.if_index != 0 {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    }
}
