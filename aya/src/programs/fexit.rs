//! Fexit programs.

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type::BPF_TRACE_FEXIT, bpf_prog_type::BPF_PROG_TYPE_TRACING},
};

use crate::programs::{
    ExpectedAttachType, FdLink, FdLinkId, ProgramData, ProgramError, ProgramType,
    define_link_wrapper, load_program, utils::attach_raw_tracepoint,
};

/// A program that can be attached to the exit point of (almost) anny kernel
/// function.
///
/// [`FExit`] programs are similar to [kretprobes](crate::programs::KProbe),
/// but the difference is that fexit has practically zero overhead to call
/// before kernel function. Fexit programs can be also attached to other eBPF
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
/// #     Ebpf(#[from] aya::EbpfError),
/// # }
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::FExit, BtfError, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut FExit = bpf.program_mut("filename_lookup").unwrap().try_into()?;
/// program.load("filename_lookup", &btf)?;
/// program.attach()?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_TRACE_FEXIT")]
#[doc(alias = "BPF_PROG_TYPE_TRACING")]
pub struct FExit {
    pub(crate) data: ProgramData<FExitLink>,
}

impl FExit {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::Tracing;

    /// Loads the program inside the kernel.
    ///
    /// Loads the program so it's executed when the kernel function `fn_name`
    /// is exited. The `btf` argument must contain the BTF info for the running
    /// kernel.
    pub fn load(&mut self, fn_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(ExpectedAttachType::AttachType(BPF_TRACE_FEXIT));
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [FExit::detach].
    pub fn attach(&mut self) -> Result<FExitLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }
}

define_link_wrapper!(FExitLink, FExitLinkId, FdLink, FdLinkId, FExit);
