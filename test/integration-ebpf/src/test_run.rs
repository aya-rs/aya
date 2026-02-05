#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::{sk_action::SK_PASS, xdp_action},
    macros::{classifier, map, socket_filter, xdp},
    maps::Array,
    programs::{SkBuffContext, TcContext, XdpContext},
};
use integration_common::test_run::{IF_INDEX, XDP_MODIGY_LEN, XDP_MODIGY_VAL};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static EXEC_COUNT: Array<u64> = Array::with_max_entries(1, 0);

#[xdp]
const fn test_xdp(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[socket_filter]
fn test_sock_filter(ctx: SkBuffContext) -> i64 {
    ctx.len().into()
}

#[classifier]
const fn test_classifier(_ctx: TcContext) -> i32 {
    SK_PASS as i32
}

#[socket_filter]
fn test_count_exec(_ctx: SkBuffContext) -> i64 {
    if let Some(count) = EXEC_COUNT.get_ptr_mut(0) {
        unsafe {
            *count += 1;
        }
    }
    0
}

#[xdp]
fn test_xdp_modify(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + XDP_MODIGY_LEN > data_end {
        return xdp_action::XDP_PASS;
    }

    let packet = data as *mut u8;
    for i in 0..XDP_MODIGY_LEN {
        unsafe {
            *packet.add(i) = XDP_MODIGY_VAL;
        }
    }

    xdp_action::XDP_PASS
}

#[xdp]
fn test_xdp_context(ctx: XdpContext) -> u32 {
    let md = ctx.ctx;
    let ingress_ifindex = unsafe { (*md).ingress_ifindex };

    if ingress_ifindex == IF_INDEX {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    }
}
