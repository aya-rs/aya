//! Integration test for `bpf_printk` variadic argument passing.
//!
//! This test verifies that `PrintkArg` correctly passes values to `bpf_trace_printk`.
//! It streams from `trace_pipe` to verify the printed values match.

use std::time::Duration;

use aya::{Ebpf, programs::UProbe};
use integration_common::printk::{MARKER, TEST_I32, TEST_U8, TEST_U16, TEST_U32, TEST_U64};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    time::timeout,
};

#[tokio::test(flavor = "multi_thread")]
async fn bpf_printk_variadic_args() {
    let trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe";

    let pipe = match tokio::fs::File::open(trace_pipe_path).await {
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

    let reader = BufReader::new(pipe);
    let mut lines = reader.lines();
    let mut trace_lines = Vec::new();

    let result = timeout(Duration::from_secs(5), async {
        while !expected.is_empty() {
            let line = lines
                .next_line()
                .await
                .expect("error reading trace_pipe")
                .expect("trace_pipe closed unexpectedly");
            if line.contains(MARKER.to_str().unwrap()) {
                expected.retain(|exp| !line.contains(exp.as_str()));
                trace_lines.push(line);
            }
        }
    })
    .await;

    let trace_content = trace_lines.join("\n");
    assert!(
        result.is_ok(),
        "timed out waiting for trace output; unsatisfied: {expected:?}\ntrace:\n{trace_content}"
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_printk() {
    core::hint::black_box(());
}
