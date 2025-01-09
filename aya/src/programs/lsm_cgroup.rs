//! LSM probes.

use std::os::fd::AsFd;

use crate::{
    generated::{bpf_attach_type::BPF_LSM_CGROUP, bpf_prog_type::BPF_PROG_TYPE_LSM},
    obj::btf::{Btf, BtfKind},
    programs::{define_link_wrapper, load_program, FdLink, FdLinkId, ProgramData, ProgramError},
    sys::{bpf_link_create, BpfLinkCreateArgs, LinkTarget, SyscallError},
};

/// A program that attaches to Linux LSM hooks with per-cgroup attachment type. Used to implement security policy and
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
/// The minimum kernel version required to use this feature is 6.0.
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
/// use aya::{Ebpf, programs::LsmCgroup, BtfError, Btf};
/// use std::fs::File;
///
/// let btf = Btf::from_sys_fs()?;
/// let file = File::open("/sys/fs/cgroup/unified").unwrap();
/// let program: &mut LsmCgroup = bpf.program_mut("lsm_prog").unwrap().try_into()?;
/// program.load("security_bprm_exec", &btf)?;
/// program.attach(file)?;
/// # Ok::<(), LsmError>(())
/// ```
///
/// [1]: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_LSM")]
pub struct LsmCgroup {
    pub(crate) data: ProgramData<LsmLink>,
}

impl LsmCgroup {
    /// Loads the program inside the kernel.
    ///
    /// # Arguments
    ///
    /// * `lsm_hook_name` - full name of the LSM hook that the program should
    ///   be attached to
    pub fn load(&mut self, lsm_hook_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_LSM_CGROUP);
        let type_name = format!("bpf_lsm_{lsm_hook_name}");
        self.data.attach_btf_id =
            Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_LSM, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [LsmCgroup::detach].
    pub fn attach<T: AsFd>(&mut self, cgroup: T) -> Result<LsmLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        let btf_id = self.data.attach_btf_id.ok_or(ProgramError::NotLoaded)?;
        let link_fd = bpf_link_create(
            prog_fd,
            LinkTarget::Fd(cgroup_fd),
            attach_type,
            0,
            Some(BpfLinkCreateArgs::TargetBtfId(btf_id)),
        )
        .map_err(|(_, io_error)| SyscallError {
            call: "bpf_link_create",
            io_error,
        })?;

        self.data.links.insert(LsmLink::new(FdLink::new(link_fd)))
    }
}

define_link_wrapper!(
    /// The link used by [LsmCgroup] programs.
    LsmLink,
    /// The type returned by [LsmCgroup::attach]. Can be passed to [LsmCgroup::detach].
    LsmLinkId,
    FdLink,
    FdLinkId,
    LsmCgroup,
);
