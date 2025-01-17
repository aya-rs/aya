//! Skmsg programs.

use std::os::fd::AsFd as _;

use crate::{
    generated::{bpf_attach_type::BPF_SK_MSG_VERDICT, bpf_prog_type::BPF_PROG_TYPE_SK_MSG},
    maps::sock::SockMapFd,
    programs::{
        define_link_wrapper, load_program, CgroupAttachMode, ProgAttachLink, ProgAttachLinkId,
        ProgramData, ProgramError,
    },
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
/// intercept_egress.insert(1234, client.as_raw_fd(), 0)?;
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
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SK_MSG, &mut self.data)
    }

    /// Attaches the program to the given sockmap.
    ///
    /// The returned value can be used to detach, see [SkMsg::detach].
    pub fn attach(&mut self, map: &SockMapFd) -> Result<SkMsgLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let link = ProgAttachLink::attach(
            prog_fd,
            map.as_fd(),
            BPF_SK_MSG_VERDICT,
            CgroupAttachMode::Single,
        )?;

        self.data.links.insert(SkMsgLink::new(link))
    }
    
    pub fn auto_attach(&self) -> Result<SkMsgLinkId, ProgramError>{
        todo!();
    }
}

define_link_wrapper!(
    /// The link used by [SkMsg] programs.
    SkMsgLink,
    /// The type returned by [SkMsg::attach]. Can be passed to [SkMsg::detach].
    SkMsgLinkId,
    ProgAttachLink,
    ProgAttachLinkId,
    SkMsg,
);
