//! Cgroup socket address programs.

pub use aya_obj::programs::CgroupSockAddrAttachType;

use crate::util::KernelVersion;
use std::{hash::Hash, os::fd::AsRawFd, path::Path};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    programs::{
        define_link_wrapper, load_program, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, SyscallError},
    VerifierLogLevel,
};

/// A program that can be used to inspect or modify socket addresses (`struct sockaddr`).
///
/// [`CgroupSockAddr`] programs can be used to inspect or modify socket addresses passed to
/// various syscalls within a [cgroup]. They can be attached to a number of different
/// places as described in [`CgroupSockAddrAttachType`].
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.17.
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::{CgroupSockAddr, CgroupSockAddrAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSockAddr = bpf.program_mut("connect4").unwrap().try_into()?;
/// egress.load()?;
/// egress.attach(file)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK_ADDR")]
pub struct CgroupSockAddr {
    pub(crate) data: ProgramData<CgroupSockAddrLink>,
    pub(crate) attach_type: CgroupSockAddrAttachType,
}

impl CgroupSockAddr {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(self.attach_type.into());
        load_program(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSockAddr::detach].
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<CgroupSockAddrLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let prog_fd = prog_fd.as_raw_fd();
        let cgroup_fd = cgroup.as_raw_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, attach_type, None, 0).map_err(
                |(_, io_error)| SyscallError {
                    call: "bpf_link_create",
                    io_error,
                },
            )?;
            self.data
                .links
                .insert(CgroupSockAddrLink::new(CgroupSockAddrLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_prog_attach",
                    io_error,
                }
            })?;

            self.data.links.insert(CgroupSockAddrLink::new(
                CgroupSockAddrLinkInner::ProgAttach(ProgAttachLink::new(
                    prog_fd,
                    cgroup_fd,
                    attach_type,
                )),
            ))
        }
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: CgroupSockAddrLinkId,
    ) -> Result<CgroupSockAddrLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program.
    ///
    /// See [CgroupSockAddr::attach].
    pub fn detach(&mut self, link_id: CgroupSockAddrLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: CgroupSockAddrAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSockAddrLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSockAddrLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSockAddrLinkInner {
    type Id = CgroupSockAddrLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            CgroupSockAddrLinkInner::Fd(fd) => CgroupSockAddrLinkIdInner::Fd(fd.id()),
            CgroupSockAddrLinkInner::ProgAttach(p) => CgroupSockAddrLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupSockAddrLinkInner::Fd(fd) => fd.detach(),
            CgroupSockAddrLinkInner::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupSockAddr] programs.
    CgroupSockAddrLink,
    /// The type returned by [CgroupSockAddr::attach]. Can be passed to [CgroupSockAddr::detach].
    CgroupSockAddrLinkId,
    CgroupSockAddrLinkInner,
    CgroupSockAddrLinkIdInner
);
