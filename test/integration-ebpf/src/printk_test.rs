//! Integration test for `bpf_printk` variadic argument passing.
//!
//! This tests that `PrintkArg` correctly passes values to the `bpf_trace_printk`
//! kernel helper. The C ABI for variadic functions requires scalar values
//! (not arrays) to be passed by value in registers.

#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{helpers::bpf_printk, macros::uprobe, programs::ProbeContext};
use integration_common::printk::{TEST_I32, TEST_U8, TEST_U16, TEST_U32, TEST_U64};
#[cfg(not(test))]
extern crate ebpf_panic;

#[uprobe]
fn test_bpf_printk(_ctx: ProbeContext) {
    // SAFETY: bpf_printk is safe with valid format string and matching args

    // Test u8 (promoted to u64)
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U8:%u", TEST_U8);
    }

    // Test u16 (promoted to u64)
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U16:%u", TEST_U16);
    }

    // Test u32 (not promoted, passed directly)
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U32:%x", TEST_U32);
    }

    // Test u64
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U64:%lx", TEST_U64);
    }

    // Test i32 (negative value, sign-extended)
    unsafe {
        bpf_printk!(b"PRINTK_TEST_I32:%d", TEST_I32);
    }

    // Test multiple arguments in one call
    unsafe {
        bpf_printk!(b"PRINTK_TEST_MULTI:%u,%x", TEST_U8, TEST_U32);
    }
}
