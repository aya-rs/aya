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
    // SAFETY: format strings match the argument types and counts.
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U8:%u", TEST_U8);
        bpf_printk!(b"PRINTK_TEST_U16:%u", TEST_U16);
        bpf_printk!(b"PRINTK_TEST_U32:%x", TEST_U32);
        bpf_printk!(b"PRINTK_TEST_U64:%lx", TEST_U64);
        bpf_printk!(b"PRINTK_TEST_I32:%d", TEST_I32);
        bpf_printk!(b"PRINTK_TEST_MULTI:%u,%x", TEST_U8, TEST_U32);
    }
}
