//! Raw tracepoints.
use std::ffi::CString;

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT;

use crate::programs::{
    FdLink, FdLinkId, ProgramData, ProgramError, define_link_wrapper, load_program,
    utils::attach_raw_tracepoint,
};

/// A program that can be attached at a pre-defined kernel trace point.
///
/// Unlike [`TracePoint`](super::TracePoint), the kernel does not pre-process
/// the arguments before calling the program.
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
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::RawTracePoint;
///
/// let program: &mut RawTracePoint = bpf.program_mut("sys_enter").unwrap().try_into()?;
/// program.load()?;
/// program.attach("sys_enter")?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_RAW_TRACEPOINT")]
pub struct RawTracePoint {
    pub(crate) data: ProgramData<RawTracePointLink>,
}

impl RawTracePoint {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_RAW_TRACEPOINT, &mut self.data)
    }

    /// Attaches the program to the given tracepoint.
    ///
    /// The returned value can be used to detach, see [RawTracePoint::detach].
    pub fn attach(&mut self, tp_name: &str) -> Result<RawTracePointLinkId, ProgramError> {
        let tp_name_c = CString::new(tp_name).unwrap();
        attach_raw_tracepoint(&mut self.data, Some(&tp_name_c))
    }
}

define_link_wrapper!(
    /// The link used by [RawTracePoint] programs.
    RawTracePointLink,
    /// The type returned by [RawTracePoint::attach]. Can be passed to [RawTracePoint::detach].
    RawTracePointLinkId,
    FdLink,
    FdLinkId,
    RawTracePoint,
);
