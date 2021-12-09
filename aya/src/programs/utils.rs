//! Common functions shared between multiple eBPF program types.
use std::{ffi::CStr, os::unix::io::RawFd};

use crate::{
    programs::{FdLink, LinkRef, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};

/// Attaches the program to a raw tracepoint.
pub(crate) fn attach_raw_tracepoint(
    program_data: &mut ProgramData,
    tp_name: Option<&CStr>,
) -> Result<LinkRef, ProgramError> {
    let prog_fd = program_data.fd_or_err()?;

    let pfd = bpf_raw_tracepoint_open(tp_name, prog_fd).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "bpf_raw_tracepoint_open".to_owned(),
            io_error,
        }
    })? as RawFd;

    Ok(program_data.link(FdLink { fd: Some(pfd) }))
}
