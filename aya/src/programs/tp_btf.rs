//! BTF-enabled raw tracepoints.

use std::os::fd::AsFd;

use crate::{
    generated::{bpf_attach_type::BPF_TRACE_RAW_TP, bpf_prog_type::BPF_PROG_TYPE_TRACING},
    obj::btf::{Btf, BtfKind},
    programs::{
        define_link_wrapper, load_program, utils::attach_raw_tracepoint, FdLink, FdLinkId,
        ProgramData, ProgramError,
    },
};

/// Marks a function as a [BTF-enabled raw tracepoint][1] eBPF program that can be attached at
/// a pre-defined kernel trace point.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See `/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError),
/// # }
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::BtfTracePoint, BtfError, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let Bpf { programs, btf_fd, .. } = &mut bpf;
/// let program: &mut BtfTracePoint = programs.get_mut("sched_process_fork").unwrap().try_into()?;
/// program.load("sched_process_fork", &btf, btf_fd.as_ref())?;
/// program.attach()?;
/// # Ok::<(), Error>(())
/// ```
///
/// [1]: https://github.com/torvalds/linux/commit/9e15db66136a14cde3f35691f1d839d950118826
#[derive(Debug)]
#[doc(alias = "BPF_TRACE_RAW_TP")]
#[doc(alias = "BPF_PROG_TYPE_TRACING")]
pub struct BtfTracePoint {
    pub(crate) data: ProgramData<BtfTracePointLink>,
}

impl BtfTracePoint {
    /// Loads the program inside the kernel.
    ///
    /// # Arguments
    ///
    /// * `tracepoint` - full name of the tracepoint that we should attach to
    /// * `btf` - btf information for the target system
    pub fn load(
        &mut self,
        tracepoint: &str,
        btf: &Btf,
        btf_fd: Option<impl AsFd>,
    ) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_TRACE_RAW_TP);
        let type_name = format!("btf_trace_{tracepoint}");
        self.data.attach_btf_id =
            Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Typedef)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data, btf_fd)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [BtfTracePoint::detach].
    pub fn attach(&mut self) -> Result<BtfTracePointLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }

    /// Detaches the program.
    ///
    /// See [BtfTracePoint::attach].
    pub fn detach(&mut self, link_id: BtfTracePointLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: BtfTracePointLinkId,
    ) -> Result<BtfTracePointLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [BtfTracePoint] programs.
    BtfTracePointLink,
    /// The type returned by [BtfTracePoint::attach]. Can be passed to [BtfTracePoint::detach].
    BtfTracePointLinkId,
    FdLink,
    FdLinkId
);
