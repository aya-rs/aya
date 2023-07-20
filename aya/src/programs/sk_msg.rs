//! Skmsg programs.

use std::os::fd::{AsFd, AsRawFd};

use crate::{
    generated::{bpf_attach_type::BPF_SK_MSG_VERDICT, bpf_prog_type::BPF_PROG_TYPE_SK_MSG},
    maps::sock::SockMapFd,
    programs::{
        define_link_wrapper, load_program, ProgAttachLink, ProgAttachLinkId, ProgramData,
        ProgramError,
    },
    sys::bpf_prog_attach,
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
/// #     Bpf(#[from] aya::BpfError)
/// # }
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use std::io::Write;
/// use std::net::TcpStream;
/// use std::os::fd::AsRawFd;
/// use aya::maps::SockHash;
/// use aya::programs::SkMsg;
///
/// let intercept_egress: SockHash<_, u32> = bpf.map("INTERCEPT_EGRESS").unwrap().try_into()?;
/// let map_fd = intercept_egress.fd()?;
///
/// let prog: &mut SkMsg = bpf.programs.get_mut("intercept_egress_packet").unwrap().try_into()?;
/// prog.load(bpf.btf_fd.as_ref())?;
/// prog.attach(map_fd)?;
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
    pub fn load(&mut self, btf_fd: Option<impl AsFd>) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SK_MSG, &mut self.data, btf_fd)
    }

    /// Attaches the program to the given sockmap.
    ///
    /// The returned value can be used to detach, see [SkMsg::detach].
    pub fn attach(&mut self, map: SockMapFd) -> Result<SkMsgLinkId, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let map_fd = map.as_raw_fd();

        bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach",
                io_error,
            }
        })?;
        self.data.links.insert(SkMsgLink::new(ProgAttachLink::new(
            prog_fd,
            map_fd,
            BPF_SK_MSG_VERDICT,
        )))
    }

    /// Detaches the program from a sockmap.
    ///
    /// See [SkMsg::attach].
    pub fn detach(&mut self, link_id: SkMsgLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: SkMsgLinkId) -> Result<SkMsgLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

define_link_wrapper!(
    /// The link used by [SkMsg] programs.
    SkMsgLink,
    /// The type returned by [SkMsg::attach]. Can be passed to [SkMsg::detach].
    SkMsgLinkId,
    ProgAttachLink,
    ProgAttachLinkId
);
