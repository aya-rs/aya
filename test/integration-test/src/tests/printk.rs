//! Integration test for bpf_printk variadic argument passing.
//!
//! This test verifies that PrintkArg correctly passes values to bpf_trace_printk.
//! It streams from trace_pipe to verify the printed values match.

use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    time::{Duration, Instant},
};

use aya::{Ebpf, programs::UProbe};
use integration_common::printk::{TEST_I32, TEST_U8, TEST_U16, TEST_U32, TEST_U64};

#[test_log::test]
fn bpf_printk_variadic_args() {
    let trace_path = "/sys/kernel/debug/tracing/trace";
    let trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe";

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

    prog.attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    // Open trace_pipe for streaming before triggering
    let pipe = File::open(trace_pipe_path).unwrap();
    let reader = BufReader::new(pipe);

    // Trigger the BPF program
    trigger_bpf_printk();

    // Stream trace_pipe with timeout, collecting PRINTK_TEST_ lines
    let timeout = Duration::from_secs(2);
    let start = Instant::now();
    let mut trace_lines = Vec::new();

    for line in reader.lines() {
        if start.elapsed() > timeout {
            break;
        }
        let line = line.unwrap();
        if line.contains("PRINTK_TEST_") {
            trace_lines.push(line);
            // Stop once we have all expected lines
            if trace_lines.len() >= 6 {
                break;
            }
        }
    }

    let trace_content = trace_lines.join("\n");

    assert!(
        !trace_lines.is_empty(),
        "no printk output captured from trace_pipe"
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
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_printk() {
    core::hint::black_box(());
}
