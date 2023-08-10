//! Cgroup sysctl programs.

use crate::util::KernelVersion;
use std::{hash::Hash, os::fd::AsRawFd};

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_SYSCTL, bpf_prog_type::BPF_PROG_TYPE_CGROUP_SYSCTL},
    programs::{
        define_link_wrapper, load_program, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, SyscallError},
};

/// A program used to watch for sysctl changes.
///
/// [`CgroupSysctl`] programs can be attached to a cgroup and will be called every
/// time a process inside that cgroup tries to read from or write to a sysctl knob in proc.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.2.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::CgroupSysctl;
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupSysctl = bpf.program_mut("cgroup_sysctl").unwrap().try_into()?;
/// program.load()?;
/// program.attach(file)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SYSCTL")]
pub struct CgroupSysctl {
    pub(crate) data: ProgramData<CgroupSysctlLink>,
}

impl CgroupSysctl {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_CGROUP_SYSCTL, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSysctl::detach].
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<CgroupSysctlLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let prog_fd = prog_fd.as_raw_fd();
        let cgroup_fd = cgroup.as_raw_fd();

        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, BPF_CGROUP_SYSCTL, None, 0).map_err(
                |(_, io_error)| SyscallError {
                    call: "bpf_link_create",
                    io_error,
                },
            )?;
            self.data
                .links
                .insert(CgroupSysctlLink::new(CgroupSysctlLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SYSCTL).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_prog_attach",
                    io_error,
                }
            })?;

            self.data
                .links
                .insert(CgroupSysctlLink::new(CgroupSysctlLinkInner::ProgAttach(
                    ProgAttachLink::new(prog_fd, cgroup_fd, BPF_CGROUP_SYSCTL),
                )))
        }
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: CgroupSysctlLinkId,
    ) -> Result<CgroupSysctlLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program.
    ///
    /// See [CgroupSysctl::attach].
    pub fn detach(&mut self, link_id: CgroupSysctlLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSysctlLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSysctlLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSysctlLinkInner {
    type Id = CgroupSysctlLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            CgroupSysctlLinkInner::Fd(fd) => CgroupSysctlLinkIdInner::Fd(fd.id()),
            CgroupSysctlLinkInner::ProgAttach(p) => CgroupSysctlLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupSysctlLinkInner::Fd(fd) => fd.detach(),
            CgroupSysctlLinkInner::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupSysctl] programs.
    CgroupSysctlLink,
    /// The type returned by [CgroupSysctl::attach]. Can be passed to [CgroupSysctl::detach].
    CgroupSysctlLinkId,
    CgroupSysctlLinkInner,
    CgroupSysctlLinkIdInner
);
