//! Cgroup socket address programs.
use thiserror::Error;

use crate::generated::bpf_attach_type;
use std::{
    hash::Hash,
    os::unix::prelude::{AsRawFd, RawFd},
};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    programs::{
        define_link_wrapper, load_program, FdLink, Link, ProgAttachLink, ProgramData, ProgramError,
    },
    sys::{bpf_link_create, bpf_prog_attach, kernel_version},
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
/// # let mut bpf = aya::Ebpf::load(&[])?;
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
                .insert(CgroupSockAddrLink(CgroupSockAddrLinkInner::Fd(
                    FdLink::new(link_fd),
                )))
        } else {
            bpf_prog_attach(prog_fd, cgroup_fd, attach_type).map_err(|(_, io_error)| {
                ProgramError::SyscallError {
                    call: "bpf_prog_attach".to_owned(),
                    io_error,
                }
            })?;

            self.data
                .links
                .insert(CgroupSockAddrLink(CgroupSockAddrLinkInner::ProgAttach(
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

/// Defines where to attach a [`CgroupSockAddr`] program.
#[derive(Copy, Clone, Debug)]
pub enum CgroupSockAddrAttachType {
    /// Attach to IPv4 bind events.
    Bind4,
    /// Attach to IPv6 bind events.
    Bind6,
    /// Attach to IPv4 connect events.
    Connect4,
    /// Attach to IPv6 connect events.
    Connect6,
    /// Attach to IPv4 getpeername events.
    GetPeerName4,
    /// Attach to IPv6 getpeername events.
    GetPeerName6,
    /// Attach to IPv4 getsockname events.
    GetSockName4,
    /// Attach to IPv6 getsockname events.
    GetSockName6,
    /// Attach to IPv4 udp_sendmsg events.
    UDPSendMsg4,
    /// Attach to IPv6 udp_sendmsg events.
    UDPSendMsg6,
    /// Attach to IPv4 udp_recvmsg events.
    UDPRecvMsg4,
    /// Attach to IPv6 udp_recvmsg events.
    UDPRecvMsg6,
}

impl From<CgroupSockAddrAttachType> for bpf_attach_type {
    fn from(s: CgroupSockAddrAttachType) -> bpf_attach_type {
        match s {
            CgroupSockAddrAttachType::Bind4 => bpf_attach_type::BPF_CGROUP_INET4_BIND,
            CgroupSockAddrAttachType::Bind6 => bpf_attach_type::BPF_CGROUP_INET6_BIND,
            CgroupSockAddrAttachType::Connect4 => bpf_attach_type::BPF_CGROUP_INET4_CONNECT,
            CgroupSockAddrAttachType::Connect6 => bpf_attach_type::BPF_CGROUP_INET6_CONNECT,
            CgroupSockAddrAttachType::GetPeerName4 => bpf_attach_type::BPF_CGROUP_INET4_GETPEERNAME,
            CgroupSockAddrAttachType::GetPeerName6 => bpf_attach_type::BPF_CGROUP_INET6_GETPEERNAME,
            CgroupSockAddrAttachType::GetSockName4 => bpf_attach_type::BPF_CGROUP_INET4_GETSOCKNAME,
            CgroupSockAddrAttachType::GetSockName6 => bpf_attach_type::BPF_CGROUP_INET6_GETSOCKNAME,
            CgroupSockAddrAttachType::UDPSendMsg4 => bpf_attach_type::BPF_CGROUP_UDP4_SENDMSG,
            CgroupSockAddrAttachType::UDPSendMsg6 => bpf_attach_type::BPF_CGROUP_UDP6_SENDMSG,
            CgroupSockAddrAttachType::UDPRecvMsg4 => bpf_attach_type::BPF_CGROUP_UDP4_RECVMSG,
            CgroupSockAddrAttachType::UDPRecvMsg6 => bpf_attach_type::BPF_CGROUP_UDP6_RECVMSG,
        }
    }
}

#[derive(Debug, Error)]
#[error("{0} is not a valid attach type for a CGROUP_SOCK_ADDR program")]
pub(crate) struct InvalidAttachType(String);

impl CgroupSockAddrAttachType {
    pub(crate) fn try_from(value: &str) -> Result<CgroupSockAddrAttachType, InvalidAttachType> {
        match value {
            "bind4" => Ok(CgroupSockAddrAttachType::Bind4),
            "bind6" => Ok(CgroupSockAddrAttachType::Bind6),
            "connect4" => Ok(CgroupSockAddrAttachType::Connect4),
            "connect6" => Ok(CgroupSockAddrAttachType::Connect6),
            "getpeername4" => Ok(CgroupSockAddrAttachType::GetPeerName4),
            "getpeername6" => Ok(CgroupSockAddrAttachType::GetPeerName6),
            "getsockname4" => Ok(CgroupSockAddrAttachType::GetSockName4),
            "getsockname6" => Ok(CgroupSockAddrAttachType::GetSockName6),
            "sendmsg4" => Ok(CgroupSockAddrAttachType::UDPSendMsg4),
            "sendmsg6" => Ok(CgroupSockAddrAttachType::UDPSendMsg6),
            "recvmsg4" => Ok(CgroupSockAddrAttachType::UDPRecvMsg4),
            "recvmsg6" => Ok(CgroupSockAddrAttachType::UDPRecvMsg6),
            _ => Err(InvalidAttachType(value.to_owned())),
        }
    }
}
