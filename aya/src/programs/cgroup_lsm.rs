//! LSM probes attached to cgroups.
use std::os::unix::prelude::{AsRawFd, RawFd};

use crate::{
    generated::{bpf_attach_type::BPF_LSM_CGROUP, bpf_prog_type::BPF_PROG_TYPE_LSM},
    obj::btf::{Btf, BtfKind},
    programs::{define_link_wrapper, load_program, FdLink, Link, ProgramData, ProgramError},
    sys::bpf_link_create,
};

/// A program that attaches to Linux LSM hooks within a [cgroup]. Used to
/// implement security policy and audit logging.
///
/// LSM probes can be attached to the kernel's [security hooks][1] to implement
/// mandatory access control policy and security auditing.
///
/// LSM probes require a kernel compiled with `CONFIG_BPF_LSM=y` and
/// `CONFIG_DEBUG_INFO_BTF=y`. In order for the probes to fire, you also need
/// the BPF LSM to be enabled through your kernel's `lsm` option. If your kernel
/// is not built with `lsm=[...],bpf` option, BPF LSM needs to be enabled
/// through the kernel's boot parameter (like `lsm=lockdown,yama,bpf`).
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
/// #     Bpf(#[from] aya::BpfError),
/// # }
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::LsmCgroup, BtfError, Btf};
/// use std::{fs::File, os::unix::prelude::AsRawFd, path::Path};
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut LsmCgroup = bpf.program_mut("lsm_prog").unwrap().try_into()?;
/// program.load("security_bprm_exec", &btf)?;
/// let cgroup = File::open(Path::new("/sys/fs/cgroup/unified/aya"))?;
/// program.attach(cgroup.as_raw_fd())?;
/// # Ok::<(), LsmError>(())
/// ```
#[derive(Debug)]
pub struct CgroupLsm {
    pub(crate) data: ProgramData<CgroupLsmLink>,
}

impl CgroupLsm {
    /// Loads the program inside the kernel.
    pub fn load(&mut self, lsm_hook_name: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_LSM_CGROUP);
        let type_name = format!("bpf_lsm_{}", lsm_hook_name);
        self.data.attach_btf_id =
            Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_LSM, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [CgroupLsm::detach].
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<CgroupLsmLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let cgroup_fd = cgroup.as_raw_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        let btf_id = self.data.attach_btf_id;

        let link_fd = bpf_link_create(prog_fd, cgroup_fd, attach_type, btf_id, 0).map_err(
            |(_, io_error)| ProgramError::SyscallError {
                call: "bpf_link_create".to_owned(),
                io_error,
            },
        )? as RawFd;
        self.data
            .links
            .insert(CgroupLsmLink(CgroupLsmLinkInner::Fd(FdLink::new(link_fd))))
    }

    /// Detaches the program.
    ///
    /// See [CgroupLsm::attach].
    pub fn detach(&mut self, link_id: CgroupLsmLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: CgroupLsmLinkId) -> Result<CgroupLsmLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupLsmLinkIdInner {
    Fd(<FdLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupLsmLinkInner {
    Fd(FdLink),
}

impl Link for CgroupLsmLinkInner {
    type Id = CgroupLsmLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            CgroupLsmLinkInner::Fd(fd) => CgroupLsmLinkIdInner::Fd(fd.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupLsmLinkInner::Fd(fd) => fd.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupLsm] programs.
    CgroupLsmLink,
    /// The type returned by [CgroupLsm::attach]. Can be passed to [CgroupLsm::detach].
    CgroupLsmLinkId,
    CgroupLsmLinkInner,
    CgroupLsmLinkIdInner
);
