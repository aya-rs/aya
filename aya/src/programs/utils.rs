//! Common functions shared between multiple eBPF program types.
use std::{ffi::CStr, io, os::unix::io::RawFd, path::Path};

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
            call: "bpf_raw_tracepoint_open".to_owned(),
            io_error,
        }
    })? as RawFd;

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
                if mount.exists() {
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
