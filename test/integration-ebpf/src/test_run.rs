#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::{sk_action::SK_PASS, xdp_action},
    macros::{classifier, map, raw_tracepoint, socket_filter, xdp},
    maps::Array,
    programs::{RawTracePointContext, SkBuffContext, TcContext, XdpContext},
};
use integration_common::test_run::{IF_INDEX, XDP_MODIFY_LEN, XDP_MODIFY_VAL};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static EXEC_COUNT: Array<u64> = Array::with_max_entries(1, 0);

/// Stores the value of arg0 passed via `BPF_PROG_TEST_RUN` `ctx_in`.
#[map]
static LAST_ARG: Array<u64> = Array::with_max_entries(1, 0);

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

#[classifier]
fn test_count_exec(_ctx: TcContext) -> i32 {
    if let Some(count) = EXEC_COUNT.get_ptr_mut(0) {
        unsafe {
            *count += 1;
        }
    }
    SK_PASS as i32
}

#[xdp]
fn test_xdp_modify(ctx: XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + XDP_MODIFY_LEN > data_end {
        return xdp_action::XDP_PASS;
    }

    let packet = data as *mut u8;
    unsafe {
        packet.write_bytes(XDP_MODIFY_VAL, XDP_MODIFY_LEN);
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

/// Reads arg0 from the raw tracepoint context and stores it in `LAST_ARG`.
///
/// When invoked via `BPF_PROG_TEST_RUN`, the kernel populates the
/// `bpf_raw_tracepoint_args` register file from the `ctx_in` byte slice passed
/// by the caller. arg(0) therefore holds the first u64 from `ctx_in`.
#[raw_tracepoint]
fn test_raw_tp(ctx: RawTracePointContext) -> i32 {
    let arg0: u64 = ctx.arg(0);
    if let Some(slot) = LAST_ARG.get_ptr_mut(0) {
        unsafe {
            *slot = arg0;
        }
    }
    0
}
