//! Integration test for `bpf_printk` argument passing.
//!
//! This test verifies that `PrintkArg` correctly passes values to `bpf_trace_printk` and
//! `bpf_trace_vprintk`. It reads trace events from `trace_pipe` to verify that `bpf-printk()`-ed
//! values match.
//!
//! NOTE: This test requires that no other process is opening `trace_pipe`, as that would prevent
//! this test from opening the file. The kernel makes sure that only one instance of open fd refers
//! to the file across the system.

use std::{
    fs::File,
    io::{self, BufRead as _, BufReader, Read},
    os::fd::AsFd,
    path::Path,
    time::{Duration, Instant},
};

use aya::{Ebpf, programs::UProbe};
use integration_common::printk::{
    MARKER, TEST_CHAR, TEST_I8, TEST_I16, TEST_I32, TEST_I64, TEST_ISIZE, TEST_U8, TEST_U16,
    TEST_U32, TEST_U64, TEST_USIZE,
};
use nix::poll::{PollFd, PollFlags, PollTimeout};

#[test_log::test]
fn bpf_printk_args() {
    let tracefs_mounts = [
        Path::new("/sys/kernel/tracing"),
        Path::new("/sys/kernel/debug/tracing"),
    ];
    let tracefs_dir = tracefs_mounts.iter().copied().find(|d| d.is_dir()).unwrap();

    // Clear the trace buffer
    // (traces emitted by this test might have been left unconsumed)
    {
        // Opening for writing with the O_TRUNC flag clears the ring buffer
        // Reference: https://docs.kernel.org/6.18/trace/ftrace.html#the-file-system
        let trace_path = tracefs_dir.join("trace");
        File::options()
            .write(true)
            .truncate(true)
            .open(&trace_path)
            .unwrap();
    }

    // Prepare to read trace_pipe with timeout
    let trace_pipe_path = tracefs_dir.join("trace_pipe");
    let file = File::open(&trace_pipe_path).unwrap();
    let reader = TimeoutReader::new(file, Duration::from_millis(100)).unwrap();
    let actual_trace_lines = BufReader::new(reader).lines();
    let total_timeout = Duration::from_secs(1);

    let mut ebpf = Ebpf::load(crate::PRINTK_TEST).unwrap();
    let prog: &mut UProbe = ebpf
        .program_mut("test_bpf_printk")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    // Trigger the BPF program
    trigger_bpf_printk();

    let marker = MARKER.to_string_lossy();
    let expected_traces = [
        format!("{marker}_CHAR_AS_U32:{:x}", TEST_CHAR as u32),
        format!("{marker}_U8:{TEST_U8}"),
        format!("{marker}_U16:{TEST_U16}"),
        format!("{marker}_U32:{TEST_U32:x}"),
        format!("{marker}_U64:{TEST_U64:x}"),
        format!("{marker}_USIZE:{TEST_USIZE}"),
        format!("{marker}_I8:{TEST_I8}"),
        format!("{marker}_I16:{TEST_I16}"),
        format!("{marker}_I32:{TEST_I32:x}"),
        format!("{marker}_I64:{TEST_I64:x}"),
        format!("{marker}_ISIZE:{TEST_ISIZE}"),
        format!("{marker}_MULTI_printk:{TEST_U8:x},{TEST_I32:x}"),
        format!("{marker}_MULTI_vprintk:{TEST_U8},{TEST_U16},{TEST_I8},{TEST_I16}"),
    ];
    let mut expected_traces = expected_traces.into_iter().peekable();

    let start = Instant::now();
    for fallible_line in actual_trace_lines {
        let Some(expected) = expected_traces.peek() else {
            break; // all test cases have been iterated over
        };
        assert!(
            start.elapsed() < total_timeout,
            "timed out before finding all test traces"
        );
        match fallible_line {
            Ok(actual_trace) => {
                if actual_trace.contains(&*marker) {
                    assert!(
                        actual_trace.contains(expected),
                        "failed - expects actual ('{actual_trace}') to contain '{expected}'"
                    );
                    expected_traces.next();
                }
            }
            Err(e) => {
                assert!(
                    e.kind() == io::ErrorKind::TimedOut,
                    "io error raised before finding all test traces: {e}"
                );
            }
        }
    }
}

struct TimeoutReader<T: AsFd + Read> {
    source: T,
    timeout: PollTimeout,
}

impl<T: AsFd + Read> TimeoutReader<T> {
    fn new(source: T, timeout: Duration) -> io::Result<Self> {
        let timeout = PollTimeout::try_from(timeout).map_err(io::Error::other)?;
        Ok(Self { source, timeout })
    }
}

impl<T: AsFd + Read> Read for TimeoutReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut fds = [PollFd::new(self.source.as_fd(), PollFlags::POLLIN)];
        loop {
            match nix::poll::poll(&mut fds, self.timeout) {
                Ok(..0) => panic!("unreachable: error is returned as Result::Err"),
                Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
                Ok(1..) => {
                    let fd = &fds[0];
                    let Some(revents) = fd.revents() else {
                        continue;
                    };
                    if !revents.contains(PollFlags::POLLIN) {
                        if revents.contains(PollFlags::POLLHUP) {
                            return Ok(0); // the other end has closed
                        }
                        continue;
                    }
                    // This remains non-blocking even without O_NONBLOCK:
                    // * trace_pipe allows only a single open fd (no race)
                    // * read() is performed only once per readiness event
                    return self.source.read(buf);
                }
                Err(err_no) => return Err(io::Error::other(err_no)),
            }
        }
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bpf_printk() {
    core::hint::black_box(());
}
