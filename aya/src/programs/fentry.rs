//! Fentry programs.

use std::os::fd::AsFd;

use crate::{
    generated::{bpf_attach_type::BPF_TRACE_FENTRY, bpf_prog_type::BPF_PROG_TYPE_TRACING},
    obj::btf::{Btf, BtfKind},
    programs::{
        define_link_wrapper, load_program, utils::attach_raw_tracepoint, FdLink, FdLinkId,
        ProgramData, ProgramError,
    },
};

/// A program that can be attached to the entry point of (almost) any kernel
/// function.
///
/// [`FEntry`] programs are similar to [kprobes](crate::programs::KProbe), but
/// the difference is that fentry has practically zero overhead to call before
/// kernel function. Fentry programs can be also attached to other eBPF
/// programs.
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
/// use aya::{Bpf, programs::FEntry, BtfError, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let Bpf { programs, btf_fd, .. } = &mut bpf;
/// let program: &mut FEntry = programs.get_mut("filename_lookup").unwrap().try_into()?;
/// program.load("filename_lookup", &btf, btf_fd.as_ref())?;
/// program.attach()?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_TRACE_FENTRY")]
#[doc(alias = "BPF_PROG_TYPE_TRACING")]
pub struct FEntry {
    pub(crate) data: ProgramData<FEntryLink>,
}

impl FEntry {
    /// Loads the program inside the kernel.
    ///
    /// Loads the program so it's executed when the kernel function `fn_name`
    /// is entered. The `btf` argument must contain the BTF info for the
    /// running kernel.
    pub fn load(
        &mut self,
        fn_name: &str,
        btf: &Btf,
        btf_fd: Option<impl AsFd>,
    ) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_TRACE_FENTRY);
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data, btf_fd)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [FEntry::detach].
    pub fn attach(&mut self) -> Result<FEntryLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }

    /// Detaches the program.
    ///
    /// See [FEntry::attach].
    pub fn detach(&mut self, link_id: FEntryLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: FEntryLinkId) -> Result<FEntryLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [FEntry] programs.
    FEntryLink,
    /// The type returned by [FEntry::attach]. Can be passed to [FEntry::detach].
    FEntryLinkId,
    FdLink,
    FdLinkId
);
