//! Integration test for `bpf_printk` variadic argument passing.
//!
//! This tests that `PrintkArg` correctly passes values to the `bpf_trace_printk`
//! kernel helper. The C ABI for variadic functions requires scalar values
//! (not arrays) to be passed by value in registers.

#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{helpers::bpf_printk, macros::uprobe, programs::ProbeContext};
use integration_common::printk::{MARKER, TEST_I32, TEST_U8, TEST_U16, TEST_U32, TEST_U64};
#[cfg(not(test))]
extern crate ebpf_panic;

#[uprobe]
fn test_bpf_printk(_ctx: ProbeContext) {
    let m = MARKER.as_ptr();
    // SAFETY: format strings match the argument types and counts.
    unsafe {
        bpf_printk!(b"%sU8:%u", m, TEST_U8);
        bpf_printk!(b"%sU16:%u", m, TEST_U16);
        bpf_printk!(b"%sU32:%x", m, TEST_U32);
        bpf_printk!(b"%sU64:%llx", m, TEST_U64);
        bpf_printk!(b"%sI32:%d", m, TEST_I32);
        bpf_printk!(b"%sMULTI:%u,%x", m, TEST_U8, TEST_U32);
    }
}
