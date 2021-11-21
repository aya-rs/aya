//! Raw tracepoints.
use std::{ffi::CString, os::unix::io::RawFd};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT,
    programs::{load_program, FdLink, OwnedLink, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};

/// A program that can be attached at a pre-defined kernel trace point, but also
/// has an access to kernel internal arguments of trace points, which
/// differentiates them from traditional tracepoint eBPF programs.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See`/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.17.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::RawTracePoint};
/// use std::convert::TryInto;
///
/// let program: &mut RawTracePoint = bpf.program_mut("sys_enter").unwrap().try_into()?;
/// program.load()?;
/// program.attach("sys_enter")?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_RAW_TRACEPOINT")]
pub struct RawTracePoint {
    pub(crate) data: ProgramData,
}

impl RawTracePoint {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_RAW_TRACEPOINT, &mut self.data)
    }

    /// Attaches the program to the given tracepoint.
    pub fn attach(&mut self, tp_name: &str) -> Result<OwnedLink, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let name = CString::new(tp_name).unwrap();

        let pfd = bpf_raw_tracepoint_open(Some(&name), prog_fd).map_err(|(_code, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_raw_tracepoint_open".to_owned(),
                io_error,
            }
        })? as RawFd;

        Ok(FdLink { fd: Some(pfd) }.into())
    }
}
