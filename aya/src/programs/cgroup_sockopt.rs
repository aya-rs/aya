//! Cgroup socket option programs.
use thiserror::Error;

use std::{
    hash::Hash,
    os::unix::prelude::{AsRawFd, RawFd},
};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT,
    programs::{
        bpf_attach_type, define_link_wrapper, load_program, FdLink, Link, ProgAttachLink,
        ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, kernel_version},
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
        let cgroup_fd = cgroup.as_raw_fd();
        let attach_type = self.data.expected_attach_type.unwrap();
        let k_ver = kernel_version().unwrap();
        if k_ver >= (5, 7, 0) {
            let link_fd = bpf_link_create(prog_fd, cgroup_fd, attach_type, None, 0).map_err(
                |(_, io_error)| ProgramError::SyscallError {
                    call: "bpf_link_create".to_owned(),
                    io_error,
                },
            )? as RawFd;
            self.data
                .links
                .insert(CgroupSockoptLink(CgroupSockoptLinkInner::Fd(FdLink::new(
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
                .insert(CgroupSockoptLink(CgroupSockoptLinkInner::ProgAttach(
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

/// Defines where to attach a [`CgroupSockopt`] program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockoptAttachType {
    /// Attach to GetSockopt.
    Get,
    /// Attach to SetSockopt.
    Set,
}

impl From<CgroupSockoptAttachType> for bpf_attach_type {
    fn from(s: CgroupSockoptAttachType) -> bpf_attach_type {
        match s {
            CgroupSockoptAttachType::Get => bpf_attach_type::BPF_CGROUP_GETSOCKOPT,
            CgroupSockoptAttachType::Set => bpf_attach_type::BPF_CGROUP_SETSOCKOPT,
        }
    }
}

#[derive(Debug, Error)]
#[error("{0} is not a valid attach type for a CGROUP_SOCKOPT program")]
pub(crate) struct InvalidAttachType(String);

impl CgroupSockoptAttachType {
    pub(crate) fn try_from(value: &str) -> Result<CgroupSockoptAttachType, InvalidAttachType> {
        match value {
            "getsockopt" => Ok(CgroupSockoptAttachType::Get),
            "setsockopt" => Ok(CgroupSockoptAttachType::Set),
            _ => Err(InvalidAttachType(value.to_owned())),
        }
    }
}
