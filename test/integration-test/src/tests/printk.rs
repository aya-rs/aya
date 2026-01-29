//! Integration test for bpf_printk variadic argument passing.
//!
//! This test verifies that PrintkArg correctly passes values to bpf_trace_printk.
//! It reads from the kernel trace buffer to verify the printed values match.
//!
//! NOTE: This test requires that no other process is reading trace_pipe, as that
//! would consume the trace entries before this test can verify them.

use std::{fs, thread, time::Duration};

use aya::{Ebpf, programs::UProbe};

/// Expected values - must match the eBPF program constants.
const MARKER: u64 = 0xABCD_1234_5678_9ABC;
const TEST_U8: u8 = 42;
const TEST_U16: u16 = 0x1234;
const TEST_U32: u32 = 0xDEAD_BEEF;
const TEST_U64: u64 = 0x0123_4567_89AB_CDEF;
const TEST_I32: i32 = -12345;

#[test_log::test]
fn bpf_printk_variadic_args() {
    // Check if trace is accessible (requires root or tracing group)
    let trace_path = "/sys/kernel/debug/tracing/trace";
    if !std::path::Path::new(trace_path).exists() {
        eprintln!("skipping test: {trace_path} not accessible (need root or tracing group)");
        return;
    }

    // Clear the trace buffer first
    if fs::write(trace_path, "").is_err() {
        eprintln!("skipping test: cannot write to trace (need root)");
        return;
    }

    let mut bpf = Ebpf::load(crate::PRINTK_TEST).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_bpf_printk")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let _link = prog
        .attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    // Trigger the BPF program
    trigger_bpf_printk();

    // Give the kernel a moment to write trace output
    thread::sleep(Duration::from_millis(100));

    // Read trace output
    let trace_content = fs::read_to_string(trace_path).unwrap();

    // Check if trace is empty (likely consumed by trace_pipe reader)
    if trace_content.contains("entries-in-buffer/entries-written: 0/0")
        || !trace_content.contains("bpf_trace_printk")
    {
        eprintln!(
            "skipping test: no printk output in trace buffer\n\
             This usually means another process is reading trace_pipe.\n\
             Close any 'cat trace_pipe' commands to run this test."
        );
        return;
    }

    // Find our marker first to ensure we're reading our output
    let marker_expected = format!("PRINTK_TEST_MARKER:{:x}", MARKER);
    assert!(
        trace_content.contains(&marker_expected),
        "marker not found in trace output - expected '{marker_expected}'\ntrace:\n{trace_content}"
    );

    // Verify each test value
    let u8_expected = format!("PRINTK_TEST_U8:{}", TEST_U8);
    assert!(
        trace_content.contains(&u8_expected),
        "u8 test failed - expected '{u8_expected}'\ntrace:\n{trace_content}"
    );

    let u16_expected = format!("PRINTK_TEST_U16:{}", TEST_U16);
    assert!(
        trace_content.contains(&u16_expected),
        "u16 test failed - expected '{u16_expected}'\ntrace:\n{trace_content}"
    );

    let u32_expected = format!("PRINTK_TEST_U32:{:x}", TEST_U32);
    assert!(
        trace_content.contains(&u32_expected),
        "u32 test failed - expected '{u32_expected}'\ntrace:\n{trace_content}"
    );

    let u64_expected = format!("PRINTK_TEST_U64:{:x}", TEST_U64);
    assert!(
        trace_content.contains(&u64_expected),
        "u64 test failed - expected '{u64_expected}'\ntrace:\n{trace_content}"
    );

    let i32_expected = format!("PRINTK_TEST_I32:{}", TEST_I32);
    assert!(
        trace_content.contains(&i32_expected),
        "i32 test failed - expected '{i32_expected}'\ntrace:\n{trace_content}"
    );

    // Verify multi-arg call
    let multi_expected = format!("PRINTK_TEST_MULTI:{},{:x}", TEST_U8, TEST_U32);
    assert!(
        trace_content.contains(&multi_expected),
        "multi-arg test failed - expected '{multi_expected}'\ntrace:\n{trace_content}"
    );

    eprintln!("bpf_printk variadic argument test passed!");
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_printk() {
    core::hint::black_box(());
}
