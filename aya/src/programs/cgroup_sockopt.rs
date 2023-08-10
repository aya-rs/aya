//! Cgroup socket option programs.

pub use aya_obj::programs::CgroupSockoptAttachType;

use crate::util::KernelVersion;
use std::{hash::Hash, os::fd::AsRawFd, path::Path};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT,
    programs::{
        define_link_wrapper, load_program, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, SyscallError},
    VerifierLogLevel,
};

/// A program that can be used to get or set options on sockets.
///
/// [`CgroupSockopt`] programs can be attached to a cgroup and will be called every
/// time a process executes getsockopt or setsockopt system call.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.3.
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
/// use aya::programs::CgroupSockopt;
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let program: &mut CgroupSockopt = bpf.program_mut("cgroup_sockopt").unwrap().try_into()?;
/// program.load()?;
/// program.attach(file)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCKOPT")]
pub struct CgroupSockopt {
    pub(crate) data: ProgramData<CgroupSockoptLink>,
    pub(crate) attach_type: CgroupSockoptAttachType,
}

impl CgroupSockopt {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(self.attach_type.into());
        load_program(BPF_PROG_TYPE_CGROUP_SOCKOPT, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSockopt::detach].
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<CgroupSockoptLinkId, ProgramError> {
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
                .insert(CgroupSockoptLink::new(CgroupSockoptLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_prog_attach",
                    io_error,
                }
            })?;

            self.data
                .links
                .insert(CgroupSockoptLink::new(CgroupSockoptLinkInner::ProgAttach(
                    ProgAttachLink::new(prog_fd, cgroup_fd, attach_type),
                )))
        }
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: CgroupSockoptLinkId,
    ) -> Result<CgroupSockoptLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Detaches the program.
    ///
    /// See [CgroupSockopt::attach].
    pub fn detach(&mut self, link_id: CgroupSockoptLinkId) -> Result<(), ProgramError> {
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
        attach_type: CgroupSockoptAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSockoptLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSockoptLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSockoptLinkInner {
    type Id = CgroupSockoptLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            CgroupSockoptLinkInner::Fd(fd) => CgroupSockoptLinkIdInner::Fd(fd.id()),
            CgroupSockoptLinkInner::ProgAttach(p) => CgroupSockoptLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupSockoptLinkInner::Fd(fd) => fd.detach(),
            CgroupSockoptLinkInner::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupSockopt] programs.
    CgroupSockoptLink,
    /// The type returned by [CgroupSockopt::attach]. Can be passed to [CgroupSockopt::detach].
    CgroupSockoptLinkId,
    CgroupSockoptLinkInner,
    CgroupSockoptLinkIdInner
);
