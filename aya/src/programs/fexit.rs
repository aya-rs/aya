//! Fexit programs.

use crate::{
    generated::{bpf_attach_type::BPF_TRACE_FEXIT, bpf_prog_type::BPF_PROG_TYPE_TRACING},
    obj::btf::{Btf, BtfKind},
    programs::{
        define_link_wrapper, load_program, unload_program, utils::attach_raw_tracepoint, FdLink,
        FdLinkId, OwnedLink, ProgramData, ProgramError,
    },
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
/// #     Bpf(#[from] aya::BpfError),
/// # }
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::FExit, BtfError, Btf};
/// use std::convert::TryInto;
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
    /// Loads the program inside the kernel.
    ///
    /// Loads the program so it's executed when the kernel function `fn_name`
    /// is exited. The `btf` argument must contain the BTF info for the running
    /// kernel.
    pub fn load(&mut self, fn_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_TRACE_FEXIT);
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data)
    }

    /// Unloads the program from the kernel.
    ///
    /// If `detach` is true, links will be detached before unloading the program.
    /// Note that OwnedLinks you obtained using [KProbe::forget_link] will not be detached.
    pub fn unload(&mut self, detach: bool) -> Result<(), ProgramError> {
        unload_program(&mut self.data, detach)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [FExit::detach].
    pub fn attach(&mut self) -> Result<FExitLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }

    /// Detaches the program.
    ///
    /// See [FExit::attach].
    pub fn detach(&mut self, link_id: FExitLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn forget_link(
        &mut self,
        link_id: FExitLinkId,
    ) -> Result<OwnedLink<FExitLink>, ProgramError> {
        Ok(OwnedLink::new(self.data.forget_link(link_id)?))
    }
}

define_link_wrapper!(
    /// The link used by [FExit] programs.
    FExitLink,
    /// The type returned by [FExit::attach]. Can be passed to [FExit::detach].
    FExitLinkId,
    FdLink,
    FdLinkId
);
