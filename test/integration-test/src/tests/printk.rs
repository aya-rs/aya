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
    io::{self, BufRead as _, BufReader, Lines, Read},
    os::fd::AsFd,
    path::Path,
    time::{Duration, Instant},
};

use aya::{Ebpf, programs::UProbe, util::KernelVersion};
use integration_common::printk::{
    MARKER, TEST_CHAR, TEST_I8, TEST_I16, TEST_I32, TEST_I64, TEST_ISIZE, TEST_U8, TEST_U16,
    TEST_U32, TEST_U64, TEST_USIZE,
};
use nix::poll::{PollFd, PollFlags, PollTimeout};

#[test_log::test]
fn bpf_printk_args() {
    let tracefs_helper =
        TracefsHelper::new(Duration::from_millis(100), Duration::from_secs(1)).unwrap();

    let mut ebpf = Ebpf::load(crate::PRINTK_TEST).unwrap();
    let prog: &mut UProbe = ebpf
        .program_mut("test_bpf_printk")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    // Clear the trace buffer then trigger the BPF program
    tracefs_helper.clear_trace_buffer().unwrap();
    trigger_bpf_printk();

    let marker = MARKER.to_string_lossy();
    let expected_traces = vec![
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
    ];

    tracefs_helper.assert_line_by_line(&marker, &expected_traces)
}

#[test_log::test]
fn bpf_printk_args_many() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 15, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, bpf_trace_vprintk() helper was introduced in 5.15"
        );
        return;
    }

    let tracefs_helper =
        TracefsHelper::new(Duration::from_millis(100), Duration::from_secs(1)).unwrap();

    let mut ebpf = Ebpf::load(crate::PRINTK_TEST).unwrap();
    let prog: &mut UProbe = ebpf
        .program_mut("test_bpf_printk_for_many_args")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_bpf_printk", "/proc/self/exe", None)
        .unwrap();

    // Clear the trace buffer then trigger the BPF program
    tracefs_helper.clear_trace_buffer().unwrap();
    trigger_bpf_printk();

    let marker = MARKER.to_string_lossy();
    let expected_traces = vec![format!(
        "{marker}_MULTI_vprintk:{TEST_U8},{TEST_U16},{TEST_I8},{TEST_I16}"
    )];

    tracefs_helper.assert_line_by_line(&marker, &expected_traces)
}

struct TracefsHelper<'a> {
    tracefs_mount: &'a Path,
    read_timeout: Duration,
    verify_timeout: Duration,
}

impl TracefsHelper<'_> {
    fn new(read_timeout: Duration, verify_timeout: Duration) -> io::Result<Self> {
        let tracefs_mount = TracefsHelper::find_tracefs_mount()?;
        Ok(Self {
            tracefs_mount,
            read_timeout,
            verify_timeout,
        })
    }

    fn find_tracefs_mount<'a>() -> io::Result<&'a Path> {
        let trace_pipe_files = [
            Path::new("/sys/kernel/tracing/trace_pipe"),
            Path::new("/sys/kernel/debug/tracing/trace_pipe"),
        ];
        trace_pipe_files
            .iter()
            .copied()
            .find(|f| f.is_file())
            .and_then(|p| p.parent())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tracefs not found"))
    }

    fn clear_trace_buffer(&self) -> io::Result<()> {
        // Opening for writing with the O_TRUNC flag clears the buffer: make sure there is no
        // traces emitted by the previous run of this test that might have been left unconsumed
        // Reference: https://docs.kernel.org/6.18/trace/ftrace.html#the-file-system
        let trace_path = self.tracefs_mount.join("trace");
        File::options()
            .write(true)
            .truncate(true)
            .open(&trace_path)?;
        Ok(())
    }

    fn assert_line_by_line(&self, marker: &str, expected_traces: &[String]) {
        let actual_trace_lines = self.open_trace_line_stream().unwrap();
        let mut expected_traces = expected_traces.iter().peekable();

        let start = Instant::now();
        for fallible_line in actual_trace_lines {
            let Some(&expected) = expected_traces.peek() else {
                break; // all test cases have been iterated over
            };
            assert!(
                start.elapsed() < self.verify_timeout,
                "timed out before finding all test traces"
            );
            match fallible_line {
                Ok(actual_trace) => {
                    if actual_trace.contains(marker) {
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

    fn open_trace_line_stream(&self) -> io::Result<Lines<BufReader<FdReaderWithTimeout<File>>>> {
        let trace_pipe_path = self.tracefs_mount.join("trace_pipe");
        let file = File::open(&trace_pipe_path)?;
        let reader = FdReaderWithTimeout::new(file, self.read_timeout)?;
        Ok(BufReader::new(reader).lines())
    }
}

struct FdReaderWithTimeout<T: AsFd + Read> {
    source: T,
    timeout: PollTimeout,
}

impl<T: AsFd + Read> FdReaderWithTimeout<T> {
    fn new(source: T, timeout: Duration) -> io::Result<Self> {
        let timeout = PollTimeout::try_from(timeout).map_err(io::Error::other)?;
        Ok(Self { source, timeout })
    }
}

impl<T: AsFd + Read> Read for FdReaderWithTimeout<T> {
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
