//! LSM Cgroup probes.

use std::{os::fd::AsFd, path::Path};

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{bpf_attach_type::BPF_LSM_CGROUP, bpf_prog_type::BPF_PROG_TYPE_LSM},
};

use crate::{
    VerifierLogLevel,
    programs::{
        FdLink, FdLinkId, ProgramData, ProgramError, define_link_wrapper,
        load_program_with_attach_type,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
};

/// A program that attaches to Linux LSM hooks with per-cgroup attachment type. Used to implement security policy and
/// audit logging.
///
/// LSM probes can be attached to the kernel's [security hooks][1] to implement mandatory
/// access control policy and security auditing.
///
/// LSM probes require a kernel compiled with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
/// In order for the probes to fire, you also need the BPF LSM to be enabled through your
/// kernel's boot parameters (like `lsm=lockdown,yama,bpf`).
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
        let Self { data } = self;
        let type_name = format!("bpf_lsm_{lsm_hook_name}");
        data.attach_btf_id = Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?);
        load_program_with_attach_type(BPF_PROG_TYPE_LSM, BPF_LSM_CGROUP, data)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(
            path,
            VerifierLogLevel::default(),
            None,
            crate::FEATURES.clone(),
        )?;
        Ok(Self { data })
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [`LsmCgroup::detach`].
    pub fn attach<T: AsFd>(&mut self, cgroup: T) -> Result<LsmLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        let link_fd = bpf_link_create(
            prog_fd,
            LinkTarget::Fd(cgroup_fd),
            BPF_LSM_CGROUP,
            0,
            // LSM cgroup links identify the hook through attach_btf_id at program load time. The
            // link_create union slot is reserved for cgroup anchor metadata instead, see
            // https://github.com/torvalds/linux/blob/5ee8dbf54602dc340d6235b1d6aa17c0f283f48c/kernel/bpf/cgroup.c#L1506-L1510
            None,
        )
        .map_err(|io_error| SyscallError {
            call: "bpf_link_create",
            io_error,
        })?;

        self.data.links.insert(LsmLink::new(FdLink::new(link_fd)))
    }
}

define_link_wrapper!(LsmLink, LsmLinkId, FdLink, FdLinkId, LsmCgroup,);
