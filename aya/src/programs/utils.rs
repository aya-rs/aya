//! Common functions shared between multiple eBPF program types.
use std::{ffi::CStr, io, os::fd::AsRawFd as _, path::Path};

use crate::{
    programs::{FdLink, Link, ProgramData, ProgramError},
    sys::{bpf_raw_tracepoint_open, SyscallError},
};

/// Attaches the program to a raw tracepoint.
pub(crate) fn attach_raw_tracepoint<T: Link + From<FdLink>>(
    program_data: &mut ProgramData<T>,
    tp_name: Option<&CStr>,
) -> Result<T::Id, ProgramError> {
    let prog_fd = program_data.fd_or_err()?;
    let prog_fd = prog_fd.as_raw_fd();
    let pfd =
        bpf_raw_tracepoint_open(tp_name, prog_fd).map_err(|(_code, io_error)| SyscallError {
            call: "bpf_raw_tracepoint_open",
            io_error,
        })?;

    program_data.links.insert(FdLink::new(pfd).into())
}

/// Find tracefs filesystem path
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
