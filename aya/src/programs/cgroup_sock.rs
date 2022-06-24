//! Cgroup socket programs.
use thiserror::Error;

use crate::generated::bpf_attach_type;
use std::{
    hash::Hash,
    os::unix::prelude::{AsRawFd, RawFd},
};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK,
    programs::{
        define_link_wrapper, load_program, FdLink, Link, OwnedLink, ProgAttachLink, ProgramData,
        ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, kernel_version},
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::fs::File;
/// use std::convert::TryInto;
/// use aya::programs::{CgroupSock, CgroupSockAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let bind: &mut CgroupSock = bpf.program_mut("bind").unwrap().try_into()?;
/// bind.load()?;
/// bind.attach(file)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK")]
pub struct CgroupSock {
    pub(crate) data: ProgramData<CgroupSockLink>,
    pub(crate) attach_type: CgroupSockAttachType,
}

impl CgroupSock {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(self.attach_type.into());
        load_program(BPF_PROG_TYPE_CGROUP_SOCK, &mut self.data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [CgroupSock::detach].
    pub fn attach<T: AsRawFd>(&mut self, cgroup: T) -> Result<CgroupSockLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let cgroup_fd = cgroup.as_raw_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        let k_ver = kernel_version().unwrap();
        if k_ver >= (5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, attach_type, None, None, 0).map_err(
                |(_, io_error)| ProgramError::SyscallError {
                    call: "bpf_link_create".to_owned(),
                    io_error,
                },
            )? as RawFd;
            self.data
                .links
                .insert(CgroupSockLink(CgroupSockLinkInner::Fd(FdLink::new(
                    link_fd,
                ))))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                ProgramError::SyscallError {
                    call: "bpf_prog_attach".to_owned(),
                    io_error,
                }
            })?;

            self.data
                .links
                .insert(CgroupSockLink(CgroupSockLinkInner::ProgAttach(
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
        link_id: CgroupSockLinkId,
    ) -> Result<OwnedLink<CgroupSockLink>, ProgramError> {
        Ok(OwnedLink::new(self.data.take_link(link_id)?))
    }

    /// Detaches the program.
    ///
    /// See [CgroupSock::attach].
    pub fn detach(&mut self, link_id: CgroupSockLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
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
            CgroupSockLinkInner::Fd(fd) => CgroupSockLinkIdInner::Fd(fd.id()),
            CgroupSockLinkInner::ProgAttach(p) => CgroupSockLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            CgroupSockLinkInner::Fd(fd) => fd.detach(),
            CgroupSockLinkInner::ProgAttach(p) => p.detach(),
        }
    }
}

define_link_wrapper!(
    /// The link used by [CgroupSock] programs.
    CgroupSockLink,
    /// The type returned by [CgroupSock::attach]. Can be passed to [CgroupSock::detach].
    CgroupSockLinkId,
    CgroupSockLinkInner,
    CgroupSockLinkIdInner
);

/// Defines where to attach a [`CgroupSock`] program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockAttachType {
    /// Called after the IPv4 bind events.
    PostBind4,
    /// Called after the IPv6 bind events.
    PostBind6,
    /// Attach to IPv4 connect events.
    SockCreate,
    /// Attach to IPv6 connect events.
    SockRelease,
}

impl Default for CgroupSockAttachType {
    // The kernel checks for a 0 attach_type and sets it to sock_create
    // We may as well do that here also
    fn default() -> Self {
        CgroupSockAttachType::SockCreate
    }
}

impl From<CgroupSockAttachType> for bpf_attach_type {
    fn from(s: CgroupSockAttachType) -> bpf_attach_type {
        match s {
            CgroupSockAttachType::PostBind4 => bpf_attach_type::BPF_CGROUP_INET4_POST_BIND,
            CgroupSockAttachType::PostBind6 => bpf_attach_type::BPF_CGROUP_INET6_POST_BIND,
            CgroupSockAttachType::SockCreate => bpf_attach_type::BPF_CGROUP_INET_SOCK_CREATE,
            CgroupSockAttachType::SockRelease => bpf_attach_type::BPF_CGROUP_INET_SOCK_RELEASE,
        }
    }
}

#[derive(Debug, Error)]
#[error("{0} is not a valid attach type for a CGROUP_SOCK program")]
pub(crate) struct InvalidAttachType(String);

impl CgroupSockAttachType {
    pub(crate) fn try_from(value: &str) -> Result<CgroupSockAttachType, InvalidAttachType> {
        match value {
            "post_bind4" => Ok(CgroupSockAttachType::PostBind4),
            "post_bind6" => Ok(CgroupSockAttachType::PostBind6),
            "sock_create" => Ok(CgroupSockAttachType::SockCreate),
            "sock_release" => Ok(CgroupSockAttachType::SockRelease),
            _ => Err(InvalidAttachType(value.to_owned())),
        }
    }
}
