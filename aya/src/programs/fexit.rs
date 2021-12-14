//! fexit programs.
use crate::{
    generated::{bpf_attach_type::BPF_TRACE_FEXIT, bpf_prog_type::BPF_PROG_TYPE_TRACING},
    obj::btf::{Btf, BtfKind},
    programs::{load_program, utils::attach_raw_tracepoint, LinkRef, ProgramData, ProgramError},
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
    pub(crate) data: ProgramData,
}

impl FExit {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    ///
    /// Loads the program so it's executed when the kernel function `fn_name`
    /// is exited. The `btf` argument must contain the BTF info for the running
    /// kernel.
    pub fn load(&mut self, fn_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_TRACE_FEXIT);
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data)
    }

    /// Attaches the program
    pub fn attach(&mut self) -> Result<LinkRef, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }
}
