//! Fexit programs.

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type::BPF_TRACE_FEXIT, bpf_prog_type::BPF_PROG_TYPE_TRACING},
};

use crate::programs::{
    FdLink, FdLinkId, ProgramData, ProgramError, ProgramType, define_link_wrapper,
    load_program_with_attach_type, utils::attach_raw_tracepoint,
};

/// A program that can be attached to the exit point of (almost) any kernel
/// function.
///
/// [`FExit`] programs are similar to [kretprobes](crate::programs::KProbe),
/// but the difference is that fexit has practically zero overhead to call
/// after the kernel function returns. Fexit programs can also be attached to
/// other eBPF programs.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Test runs
///
/// [`TestRun`](crate::programs::TestRun) support for [`FExit`] programs uses
/// the kernel's tracing `BPF_PROG_TEST_RUN` handler. That handler does not call
/// the function passed to [`FExit::load`]. Instead, it runs the kernel's fixed
/// `bpf_fentry_test*` sequence, so the [`FExit`] program is executed only when
/// it is attached to one of those built-in test targets.
/// <https://github.com/torvalds/linux/blob/v7.1-rc4/net/bpf/test_run.c#L702-L715>
///
/// A successful test-run syscall means the kernel sequence completed. To check
/// that an [`FExit`] program ran, record and verify an explicit side effect such
/// as a map update. `Ok(())` does not mean this [`FExit`] program ran.
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
        let Self { data } = self;
        data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program_with_attach_type(BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT, data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [`FExit::detach`].
    pub fn attach(&mut self) -> Result<FExitLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }
}

define_link_wrapper!(FExitLink, FExitLinkId, FdLink, FdLinkId, FExit);
