//! Integration test for `bpf_printk` variadic argument passing.
//!
//! This test verifies that `PrintkArg` correctly passes values to `bpf_trace_printk`.
//! It streams from `trace_pipe` to verify the printed values match.

use std::{
    fs::OpenOptions,
    io::{BufRead as _, BufReader},
    time::{Duration, Instant},
};

use aya::{Ebpf, programs::UProbe};
use integration_common::printk::{MARKER, TEST_I32, TEST_U8, TEST_U16, TEST_U32, TEST_U64};

#[test_log::test]
fn bpf_printk_variadic_args() {
    let trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe";

    // Open trace_pipe for streaming; truncate clears the trace buffer.
    let pipe = match OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open(trace_pipe_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("skipping test: cannot open {trace_pipe_path}: {e}");
            return;
        }
    };

    let mut bpf = Ebpf::load(crate::PRINTK_TEST).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_bpf_printk")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    prog.attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    let reader = BufReader::new(pipe);

    // Trigger the BPF program
    trigger_bpf_printk();

    let mut expected = vec![
        format!("PRINTK_TEST_U8:{TEST_U8}"),
        format!("PRINTK_TEST_U16:{TEST_U16}"),
        format!("PRINTK_TEST_U32:{TEST_U32:x}"),
        format!("PRINTK_TEST_U64:{TEST_U64:x}"),
        format!("PRINTK_TEST_I32:{TEST_I32}"),
        format!("PRINTK_TEST_MULTI:{TEST_U8},{TEST_U32:x}"),
    ];

    let timeout = Duration::from_secs(2);
    let start = Instant::now();
    let mut trace_lines = Vec::new();

    for line in reader.lines() {
        if start.elapsed() > timeout || expected.is_empty() {
            break;
        }
        let line = line.unwrap();
        if line.contains(MARKER.to_str().unwrap()) {
            expected.retain(|exp| !line.contains(exp.as_str()));
            trace_lines.push(line);
        }
    }

    let trace_content = trace_lines.join("\n");

    assert!(
        expected.is_empty(),
        "unsatisfied expectations: {expected:?}\ntrace:\n{trace_content}"
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_printk() {
    core::hint::black_box(());
}
