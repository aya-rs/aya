//! Skmsg programs.

use std::os::fd::AsFd as _;

use aya_obj::generated::{
    bpf_attach_type::BPF_SK_MSG_VERDICT, bpf_prog_type::BPF_PROG_TYPE_SK_MSG,
};

use crate::{
    maps::sock::SockMapFd,
    programs::{
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, id_as_key, impl_try_into_fdlink, load_program_with_attach_type,
    },
    sys::{LinkTarget, SyscallError, bpf_link_create},
    util::KernelVersion,
};

/// A program used to intercept messages sent with `sendmsg()`/`sendfile()`.
///
/// [`SkMsg`] programs are attached to [socket maps], and can be used inspect,
/// filter and redirect messages sent on sockets. See also [`SockMap`] and
/// [`SockHash`].
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.17.
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
/// use std::io::Write;
/// use std::net::TcpStream;
/// use std::os::fd::AsRawFd;
/// use aya::maps::SockHash;
/// use aya::programs::SkMsg;
///
/// let intercept_egress: SockHash<_, u32> = bpf.map("INTERCEPT_EGRESS").unwrap().try_into()?;
/// let map_fd = intercept_egress.fd().try_clone()?;
///
/// let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&map_fd)?;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// let mut intercept_egress: SockHash<_, u32> = bpf.map_mut("INTERCEPT_EGRESS").unwrap().try_into()?;
///
/// intercept_egress.insert(&1234, client.as_raw_fd(), 0)?;
///
/// // the write will be intercepted
/// client.write_all(b"foo")?;
/// # Ok::<(), Error>(())
/// ```
///
/// [socket maps]: crate::maps::sock
/// [`SockMap`]: crate::maps::SockMap
/// [`SockHash`]: crate::maps::SockHash
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_MSG")]
pub struct SkMsg {
    pub(crate) data: ProgramData<SkMsgLink>,
}

impl SkMsg {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SkMsg;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_SK_MSG, BPF_SK_MSG_VERDICT, data)
    }

    /// Attaches the program to the given sockmap.
    ///
    /// The returned value can be used to detach, see [`SkMsg::detach`].
    pub fn attach(&mut self, map: &SockMapFd) -> Result<SkMsgLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let attach_type = BPF_SK_MSG_VERDICT;
        if KernelVersion::at_least(5, 7, 0) {
            let link_fd = bpf_link_create(
                prog_fd,
                LinkTarget::Fd(map.as_fd()),
                attach_type,
                CgroupAttachMode::Single.into(),
                None,
            )
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            self.data
                .links
                .insert(SkMsgLink::new(SkMsgLinkInner::Fd(FdLink::new(link_fd))))
        } else {
            let link = ProgAttachLink::attach(
                prog_fd,
                map.as_fd(),
                attach_type,
                CgroupAttachMode::Single,
            )?;
            self.data
                .links
                .insert(SkMsgLink::new(SkMsgLinkInner::ProgAttach(link)))
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum SkMsgLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum SkMsgLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for SkMsgLinkInner {
    type Id = SkMsgLinkIdInner;
    type Error = ProgramError;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => SkMsgLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => SkMsgLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), Self::Error> {
        match self {
            Self::Fd(fd) => fd.detach().map_err(Into::into),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(SkMsgLinkInner, SkMsgLinkIdInner);

define_link_wrapper!(
    SkMsgLink,
    SkMsgLinkId,
    SkMsgLinkInner,
    SkMsgLinkIdInner,
    SkMsg,
);

impl_try_into_fdlink!(SkMsgLink, SkMsgLinkInner);
