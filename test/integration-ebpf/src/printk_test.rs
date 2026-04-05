//! Integration test for `bpf_printk` argument passing.

#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{helpers::bpf_printk, macros::uprobe, programs::ProbeContext};
use integration_common::printk::{
    C_MARKER, TEST_CHAR, TEST_I8, TEST_I16, TEST_I32, TEST_I64, TEST_ISIZE, TEST_U8, TEST_U16,
    TEST_U32, TEST_U64, TEST_USIZE,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[uprobe]
fn test_bpf_printk(_ctx: ProbeContext) {
    let m = C_MARKER.as_ptr();
    // SAFETY: format strings match the argument types and counts.
    unsafe {
        bpf_printk!(C_MARKER);

        bpf_printk!(c"%s_CHAR_AS_U32:%x", m, TEST_CHAR);
        bpf_printk!(c"%s_U8:%u", m, TEST_U8);
        bpf_printk!(c"%s_U16:%u", m, TEST_U16);
        bpf_printk!(c"%s_U32:%x", m, TEST_U32);
        bpf_printk!(c"%s_U64:%llx", m, TEST_U64);
        bpf_printk!(c"%s_USIZE:%llu", m, TEST_USIZE);
        bpf_printk!(c"%s_I8:%d", m, TEST_I8);
        bpf_printk!(c"%s_I16:%d", m, TEST_I16);
        bpf_printk!(c"%s_I32:%x", m, TEST_I32);
        bpf_printk!(c"%s_I64:%llx", m, TEST_I64);
        bpf_printk!(c"%s_ISIZE:%lld", m, TEST_ISIZE);
        bpf_printk!(c"%s_MULTI_printk:%x,%x", m, TEST_U8, TEST_I32);
    }
}

#[uprobe]
fn test_bpf_printk_for_many_args(_ctx: ProbeContext) {
    let m = C_MARKER.as_ptr();
    // SAFETY: format strings match the argument types and counts.
    unsafe {
        bpf_printk!(
            c"%s_MULTI_vprintk:%u,%u,%d,%d",
            m,
            TEST_U8,
            TEST_U16,
            TEST_I8,
            TEST_I16
        );
    }
}
