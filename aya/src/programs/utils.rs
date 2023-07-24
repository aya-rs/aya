//! Common functions shared between multiple eBPF program types.
use std::{
    ffi::CStr,
    fs::File,
    io,
    io::{BufRead, BufReader},
    os::unix::io::RawFd,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    programs::{FdLink, Link, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};

/// Attaches the program to a raw tracepoint.
pub(crate) fn attach_raw_tracepoint<T: Link + From<FdLink>>(
    program_data: &mut ProgramData<T>,
    tp_name: Option<&CStr>,
) -> Result<T::Id, ProgramError> {
    let prog_fd = program_data.fd_or_err()?;

    let pfd = bpf_raw_tracepoint_open(tp_name, prog_fd).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "bpf_raw_tracepoint_open",
            io_error,
        }
    })? as RawFd;

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

/// Get the real (wall-clock) boot time.
pub(crate) fn boot_time() -> SystemTime {
    let mut time = unsafe { std::mem::zeroed::<libc::timespec>() };

    let ret = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
    assert_eq!(ret, 0, "failed to get system bootime");
    let libc::timespec { tv_sec, tv_nsec } = time;

    let dur_since_boot = Duration::new(tv_sec as u64, tv_nsec as u32);

    let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut time) };
    assert_eq!(ret, 0, "failed to get system realtime");
    let libc::timespec { tv_sec, tv_nsec } = time;

    let dur_since_epoch = Duration::new(tv_sec as u64, tv_nsec as u32);

    UNIX_EPOCH + (dur_since_epoch - dur_since_boot)
}

/// Get the specified information from a file descriptor's fdinfo.
pub(crate) fn get_fdinfo(fd: RawFd, key: &str) -> Result<u32, ProgramError> {
    let info = File::open(format!("/proc/self/fdinfo/{}", fd))?;
    let reader = BufReader::new(info);
    for line in reader.lines() {
        match line {
            Ok(l) => {
                if !l.contains(key) {
                    continue;
                }

                let (_key, val) = l.rsplit_once('\t').unwrap();

                return Ok(val.parse().unwrap());
            }
            Err(e) => return Err(ProgramError::IOError(e)),
        }
    }

    Ok(0)
}
