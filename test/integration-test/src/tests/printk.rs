//! Integration test for `bpf_printk` argument passing.
//!
//! This test verifies that `PrintkArg` correctly passes values to
//! `bpf_trace_printk` and `bpf_trace_vprintk`. It reads trace events from
//! `trace_pipe` to verify that `bpf-printk()`-ed values match.
//!
//! NOTE: This test requires that no other process is opening `trace_pipe`, as
//! that would prevent this test from opening the file. The kernel makes sure
//! that only one instance of open fd refers to the file across the system.

use std::{
    fs::File,
    io::{ErrorKind, Read as _},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

use aya::{Ebpf, programs::UProbe, util::KernelVersion};
use integration_common::printk::{
    MARKER, TEST_CHAR, TEST_I8, TEST_I16, TEST_I32, TEST_I64, TEST_ISIZE, TEST_U8, TEST_U16,
    TEST_U32, TEST_U64, TEST_USIZE,
};
use test_case::test_case;
use tokio::{
    io::{Interest, unix::AsyncFd},
    time::{Duration, timeout},
};

#[test_case(
    None,
    "test_bpf_printk",
    vec![
        format!("{MARKER}_CHAR_AS_U32:{:x}", TEST_CHAR as u32),
        format!("{MARKER}_U8:{TEST_U8}"),
        format!("{MARKER}_U16:{TEST_U16}"),
        format!("{MARKER}_U32:{TEST_U32:x}"),
        format!("{MARKER}_U64:{TEST_U64:x}"),
        format!("{MARKER}_USIZE:{TEST_USIZE}"),
        format!("{MARKER}_I8:{TEST_I8}"),
        format!("{MARKER}_I16:{TEST_I16}"),
        format!("{MARKER}_I32:{TEST_I32:x}"),
        format!("{MARKER}_I64:{TEST_I64:x}"),
        format!("{MARKER}_ISIZE:{TEST_ISIZE}"),
        format!("{MARKER}_MULTI_printk:{TEST_U8:x},{TEST_I32:x}"),
    ];
    "few"
)]
#[test_case(
    Some(("bpf_trace_vprintk", KernelVersion::new(5, 15, 0))),
    "test_bpf_printk_for_many_args",
    vec![
        format!("{MARKER}_MULTI_vprintk:{TEST_U8},{TEST_U16},{TEST_I8},{TEST_I16}")
    ];
    "many"
)]
#[tokio::test]
async fn bpf_printk(
    minimum_kernel_version: Option<(&str, KernelVersion)>,
    bpf_program_name: &str,
    expected: Vec<String>,
) {
    if let Some((helper_name, minimum_kernel_version)) = minimum_kernel_version {
        let kernel_version = KernelVersion::current().unwrap();
        if kernel_version < minimum_kernel_version {
            eprintln!(
                "skipping test on kernel {kernel_version:?}, {helper_name} was introduced in {minimum_kernel_version:?}"
            );
            return;
        }
    }

    let mut ebpf = Ebpf::load(crate::PRINTK_TEST).unwrap();
    let prog: &mut UProbe = ebpf
        .program_mut(bpf_program_name)
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    let tracefs_mount = "/sys/kernel/debug/tracing";
    let tracefs_mount = Path::new(tracefs_mount);

    // Opening for writing with the O_TRUNC flag clears the buffer: make sure there is no
    // traces emitted by the previous run of this test that might have been left unconsumed
    // Reference: https://docs.kernel.org/6.18/trace/ftrace.html#the-file-system
    let trace_path = tracefs_mount.join("trace");
    File::options()
        .write(true)
        .truncate(true)
        .open(&trace_path)
        .unwrap_or_else(|err| {
            panic!(
                "failed to open trace path: {}: {err:?}",
                trace_path.display()
            )
        });

    let trace_pipe_path = tracefs_mount.join("trace_pipe");
    let pipe = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&trace_pipe_path)
        .unwrap_or_else(|err| {
            panic!(
                "failed to open trace pipe path: {}: {err:?}",
                trace_pipe_path.display()
            )
        });

    let mut pipe = AsyncFd::with_interest(pipe, Interest::READABLE).unwrap();

    let mut trace_lines = Vec::new();
    let mut read_buf = String::new();

    trigger_bpf_printk();

    let result = timeout(Duration::from_secs(5), async {
        while trace_lines.len() != expected.len() {
            let mut guard = pipe
                .readable_mut()
                .await
                .expect("error waiting for trace_pipe");
            match guard.get_inner_mut().read_to_string(&mut read_buf) {
                Ok(n) => {
                    panic!("trace_pipe EOF: n={n}");
                }
                Err(err) => {
                    assert_eq!(
                        err.kind(),
                        ErrorKind::WouldBlock,
                        "error reading trace_pipe: {err:?}"
                    );
                }
            }
            guard.clear_ready();

            loop {
                let buf = read_buf.as_str();
                let Some(start) = buf.find(MARKER) else { break };
                let buf = &buf[start..];
                let Some(end) = buf.find('\n') else { break };
                let buf = &buf[..end];

                trace_lines.push(buf.to_string());

                read_buf.drain(..start + end + 1);
            }
            // Discard unrelated lines.
            while let Some(i) = read_buf.find('\n') {
                read_buf.drain(..i + 1);
            }
        }
    })
    .await;

    assert_eq!(trace_lines, expected, "timeout={}", result.is_ok());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_printk() {
    core::hint::black_box(());
}
