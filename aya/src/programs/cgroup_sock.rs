//! Cgroup socket programs.

use log::warn;
use std::{hash::Hash, os::fd::AsFd, path::Path};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK;
pub use aya_obj::programs::CgroupSockAttachType;

use crate::{
    VerifierLogLevel,
    programs::{
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, id_as_key, impl_try_into_fdlink, load_program,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
    util::KernelVersion,
};

/// A program that is called on socket creation, bind and release.
///
/// [`CgroupSock`] programs can be used to allow or deny socket creation from
/// within a [cgroup], or they can be used to monitor and gather statistics.
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.10.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
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
/// use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let bind: &mut CgroupSock = bpf.program_mut("bind").unwrap().try_into()?;
/// bind.load()?;
/// bind.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK")]
pub struct CgroupSock {
    pub(crate) data: ProgramData<CgroupSockLink>,
    pub(crate) attach_type: CgroupSockAttachType,
}

impl CgroupSock {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSock;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(self.attach_type.into());
        load_program(BPF_PROG_TYPE_CGROUP_SOCK, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSock::detach].
    ///
    /// # Warning
    ///
    /// attach modes other than CgroupAttachMode::default() may not be passed on to kernel BPF APIs
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<CgroupSockLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        if KernelVersion::at_least(5, 7, 0) {
            if mode != CgroupAttachMode::default() {
                warn!(
                    "CgroupAttachMode {:?} will not be passed on to bpf_link_create",
                    mode
                );
            }
            let link_fd = bpf_link_create(prog_fd, LinkTarget::Fd(cgroup_fd), attach_type, 0, None)
                .map_err(|io_error| SyscallError {
                    call: "bpf_link_create",
                    io_error,
                })?;
            self.data
                .links
                .insert(CgroupSockLink::new(CgroupSockLinkInner::Fd(FdLink::new(
                    link_fd,
                ))))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, attach_type, mode)?;

            self.data
                .links
                .insert(CgroupSockLink::new(CgroupSockLinkInner::ProgAttach(link)))
        }
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: CgroupSockAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSockLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSockLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSockLinkInner {
    type Id = CgroupSockLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => CgroupSockLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => CgroupSockLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(CgroupSockLinkInner, CgroupSockLinkIdInner);

define_link_wrapper!(
    CgroupSockLink,
    CgroupSockLinkId,
    CgroupSockLinkInner,
    CgroupSockLinkIdInner,
    CgroupSock,
);

impl_try_into_fdlink!(CgroupSockLink, CgroupSockLinkInner);
