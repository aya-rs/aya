//! LSM probes.

use crate::{
    generated::{bpf_attach_type::BPF_LSM_MAC, bpf_prog_type::BPF_PROG_TYPE_LSM},
    obj::btf::{Btf, BtfKind},
    programs::{
        define_link_wrapper, load_program, utils::attach_raw_tracepoint, FdLink, FdLinkId,
        ProgramData, ProgramError,
    },
};

/// A program that attaches to Linux LSM hooks. Used to implement security policy and
/// audit logging.
///
/// LSM probes can be attached to the kernel's [security hooks][1] to implement mandatory
/// access control policy and security auditing.
///
/// LSM probes require a kernel compiled with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
/// In order for the probes to fire, you also need the BPF LSM to be enabled through your
/// kernel's boot paramters (like `lsm=lockdown,yama,bpf`).
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.7.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum LsmError {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError),
/// # }
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::Lsm, BtfError, Btf};
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut Lsm = bpf.program_mut("lsm_prog").unwrap().try_into()?;
/// program.load("security_bprm_exec", &btf)?;
/// program.attach()?;
/// # Ok::<(), LsmError>(())
/// ```
///
/// [1]: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_LSM")]
pub struct Lsm {
    pub(crate) data: ProgramData<LsmLink>,
}

impl Lsm {
    /// Loads the program inside the kernel.
    ///
    /// # Arguments
    ///
    /// * `lsm_hook_name` - full name of the LSM hook that the program should
    ///   be attached to
    pub fn load(&mut self, lsm_hook_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_LSM_MAC);
        let type_name = format!("bpf_lsm_{lsm_hook_name}");
        self.data.attach_btf_id =
            Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_LSM, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [Lsm::detach].
    pub fn attach(&mut self) -> Result<LsmLinkId, ProgramError> {
        attach_raw_tracepoint(&mut self.data, None)
    }
}

define_link_wrapper!(
    /// The link used by [Lsm] programs.
    LsmLink,
    /// The type returned by [Lsm::attach]. Can be passed to [Lsm::detach].
    LsmLinkId,
    FdLink,
    FdLinkId,
    Lsm,
);
