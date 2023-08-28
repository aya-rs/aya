//! Common functions shared between multiple eBPF program types.
use std::{
    ffi::CStr,
    fs::File,
    io::{self, BufRead, BufReader},
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    programs::{FdLink, Link, ProgramData, ProgramError},
    sys::{bpf_raw_tracepoint_open, SyscallError},
};

/// Attaches the program to a raw tracepoint.
pub(crate) fn attach_raw_tracepoint<T: Link + From<FdLink>>(
    program_data: &mut ProgramData<T>,
    tp_name: Option<&CStr>,
) -> Result<T::Id, ProgramError> {
    let prog_fd = program_data.fd()?;
    let prog_fd = prog_fd.as_fd();
    let pfd =
        bpf_raw_tracepoint_open(tp_name, prog_fd).map_err(|(_code, io_error)| SyscallError {
            call: "bpf_raw_tracepoint_open",
            io_error,
        })?;

    program_data.links.insert(FdLink::new(pfd).into())
}

/// Find tracefs filesystem path.
pub(crate) fn find_tracefs_path() -> Result<&'static Path, ProgramError> {
    lazy_static::lazy_static! {
        static ref TRACE_FS: Option<&'static Path> = {
            let known_mounts = [
                Path::new("/sys/kernel/tracing"),
                Path::new("/sys/kernel/debug/tracing"),
            ];

            for mount in known_mounts {
                // Check that the mount point exists and is not empty
                // Documented here: (https://www.kernel.org/doc/Documentation/trace/ftrace.txt)
                // In some cases, tracefs will only mount at /sys/kernel/debug/tracing
                // but, the kernel will still create the directory /sys/kernel/tracing.
                // The user may be expected to manually mount the directory in order for it to
                // exist in /sys/kernel/tracing according to the documentation.
                if mount.exists() && mount.read_dir().ok()?.next().is_some() {
                    return Some(mount);
                }
            }
            None
        };
    }

    TRACE_FS
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "tracefs not found").into())
}

/// The time at which the system is booted.
pub(crate) fn boot_time() -> SystemTime {
    let get_time = |clock_id| {
        let mut time = unsafe { std::mem::zeroed::<libc::timespec>() };
        assert_eq!(
            unsafe { libc::clock_gettime(clock_id, &mut time) },
            0,
            "clock_gettime({}, _)",
            clock_id
        );
        let libc::timespec { tv_sec, tv_nsec } = time;

        Duration::new(tv_sec as u64, tv_nsec as u32)
    };
    let since_boot = get_time(libc::CLOCK_BOOTTIME);
    let since_epoch = get_time(libc::CLOCK_REALTIME);
    UNIX_EPOCH + since_epoch - since_boot
}

/// Get the specified information from a file descriptor's fdinfo.
pub(crate) fn get_fdinfo(fd: BorrowedFd<'_>, key: &str) -> Result<u32, ProgramError> {
    let info = File::open(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
    let reader = BufReader::new(info);
    for line in reader.lines() {
        let line = line?;
        if !line.contains(key) {
            continue;
        }

        let (_key, val) = line.rsplit_once('\t').unwrap();

        return Ok(val.parse().unwrap());
    }

    Ok(0)
}
