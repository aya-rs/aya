//! Socket option programs.
use std::os::fd::AsFd;

use crate::{
    generated::{bpf_attach_type::BPF_CGROUP_SOCK_OPS, bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS},
    programs::{
        define_link_wrapper, load_program, CgroupAttachMode, FdLink, Link, ProgAttachLink,
        ProgramData, ProgramError,
    },
    sys::{bpf_link_create, LinkTarget, SyscallError},
    util::KernelVersion,
};

/// A program used to work with sockets.
///
/// [`SockOps`] programs can access or set socket options, connection
/// parameters, watch connection state changes and more. They are attached to
/// cgroups.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.13.
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
/// use aya::programs::{CgroupAttachMode, SockOps};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let prog: &mut SockOps = bpf.program_mut("intercept_active_sockets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCK_OPS")]
pub struct SockOps {
    pub(crate) data: ProgramData<SockOpsLink>,
}

impl SockOps {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCK_OPS, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [SockOps::detach].
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<SockOpsLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        let attach_type = BPF_CGROUP_SOCK_OPS;
        if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                attach_type,
                None,
                mode.into(),
                None,
                None,
            )
            .map_err(|(_, io_error)| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            self.data
                .links
                .insert(SockOpsLink::new(SockOpsLinkInner::Fd(FdLink::new(link_fd))))
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, attach_type, mode)?;

            self.data
                .links
                .insert(SockOpsLink::new(SockOpsLinkInner::ProgAttach(link)))
        }
    }

    /// Detaches the program.
    ///
    /// See [SockOps::attach].
    pub fn detach(&mut self, link_id: SockOpsLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: SockOpsLinkId) -> Result<SockOpsLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum SockOpsLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum SockOpsLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for SockOpsLinkInner {
    type Id = SockOpsLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => SockOpsLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => SockOpsLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [SockOps] programs.
    SockOpsLink,
    /// The type returned by [SockOps::attach]. Can be passed to [SockOps::detach].
    SockOpsLinkId,
    SockOpsLinkInner,
    SockOpsLinkIdInner
);
