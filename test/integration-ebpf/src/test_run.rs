#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::{sk_action::SK_PASS, xdp_action},
    macros::{classifier, map, socket_filter, xdp},
    maps::Array,
    programs::{SkBuffContext, TcContext, XdpContext},
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static EXEC_COUNT: Array<u64> = Array::with_max_entries(1, 0);

#[xdp]
fn test_xdp(ctx: XdpContext) -> u32 {
    match try_test_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline]
fn try_test_xdp(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[socket_filter]
fn test_sock_filter(ctx: SkBuffContext) -> i64 {
    ctx.len().into()
}

#[classifier]
fn test_classifier(_ctx: TcContext) -> i32 {
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
    match try_test_xdp_modify(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline]
fn try_test_xdp_modify(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 16 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let packet = data as *mut u8;
    for i in 0..16 {
        unsafe {
            *packet.add(i) = 0xAAu8;
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[xdp]
fn test_xdp_context(ctx: XdpContext) -> u32 {
    match try_test_xdp_context(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline]
fn try_test_xdp_context(ctx: XdpContext) -> Result<u32, u32> {
    // hardcoded expected value
    const EXPECTED_IF: u32 = 1;

    let md = ctx.ctx;
    let rx_queue = unsafe { (*md).ingress_ifindex };

    if rx_queue == EXPECTED_IF {
        Ok(xdp_action::XDP_PASS)
    } else {
        Ok(xdp_action::XDP_DROP)
    }
}
