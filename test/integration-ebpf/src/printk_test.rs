//! Integration test for bpf_printk variadic argument passing.
//!
//! This tests that PrintkArg correctly passes values to the bpf_trace_printk
//! kernel helper. The C ABI for variadic functions requires scalar values
//! (not arrays) to be passed by value in registers.

#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    cty::c_long,
    helpers::bpf_printk,
    macros::uprobe,
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

/// Magic marker to identify our trace output.
const MARKER: u64 = 0xABCD_1234_5678_9ABC;

/// Test values - chosen to be easily identifiable in trace output.
const TEST_U8: u8 = 42;
const TEST_U16: u16 = 0x1234;
const TEST_U32: u32 = 0xDEAD_BEEF;
const TEST_U64: u64 = 0x0123_4567_89AB_CDEF;
const TEST_I32: i32 = -12345;

#[uprobe]
fn test_bpf_printk(_ctx: ProbeContext) -> Result<(), c_long> {
    // Print marker so test can identify our output
    // SAFETY: bpf_printk is safe with valid format string and matching args
    unsafe {
        bpf_printk!(b"PRINTK_TEST_MARKER:%lx", MARKER);
    }

    // Test u8 (promoted to u64)
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U8:%u", TEST_U8);
    }

    // Test u16 (promoted to u64)
    unsafe {
        bpf_printk!(b"PRINTK_TEST_U16:%u", TEST_U16);
    }

    // Test u32
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

    Ok(())
}
