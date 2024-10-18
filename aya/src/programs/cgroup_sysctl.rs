//! Cgroup sysctl programs.

use std::{hash::Hash, os::fd::AsFd};

use crate::{
    errors::{LinkError, ProgramError},
    generated::{bpf_attach_type::BPF_CGROUP_SYSCTL, bpf_prog_type::BPF_PROG_TYPE_CGROUP_SYSCTL},
    programs::{
        define_link_wrapper, load_program, CgroupAttachMode, FdLink, Link, ProgAttachLink,
        ProgramData,
    },
    sys::{bpf_link_create, LinkTarget},
    util::KernelVersion,
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
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::{CgroupAttachMode, CgroupSysctl};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupSysctl = bpf.program_mut("cgroup_sysctl").unwrap().try_into()?;
/// program.load()?;
/// program.attach(file, CgroupAttachMode::Single)?;
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
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<CgroupSysctlLinkId, LinkError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();

        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                BPF_CGROUP_SYSCTL,
                None,
                mode.into(),
                None,
            )?;
            self.data
                .links
                .insert(CgroupSysctlLink::new(CgroupSysctlLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, BPF_CGROUP_SYSCTL, mode)?;

            self.data
                .links
                .insert(CgroupSysctlLink::new(CgroupSysctlLinkInner::ProgAttach(
                    link,
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
    ) -> Result<CgroupSysctlLink, LinkError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program.
    ///
    /// See [CgroupSysctl::attach].
    pub fn detach(&mut self, link_id: CgroupSysctlLinkId) -> Result<(), LinkError> {
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
            Self::Fd(fd) => CgroupSysctlLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => CgroupSysctlLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), LinkError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
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
