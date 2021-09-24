use crate::{
    generated::{bpf_attach_type::BPF_SK_MSG_VERDICT, bpf_prog_type::BPF_PROG_TYPE_SK_MSG},
    maps::sock::SocketMap,
    programs::{load_program, LinkRef, ProgAttachLink, ProgramData, ProgramError},
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
/// use std::convert::{TryFrom, TryInto};
/// use std::io::Write;
/// use std::net::TcpStream;
/// use std::os::unix::io::AsRawFd;
/// use aya::maps::SockHash;
/// use aya::programs::SkMsg;
///
/// let mut intercept_egress = SockHash::try_from(bpf.map_mut("INTERCEPT_EGRESS")?)?;
/// let prog: &mut SkMsg = bpf.program_mut("intercept_egress_packet")?.try_into()?;
/// prog.load()?;
/// prog.attach(&intercept_egress)?;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
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
    pub(crate) data: ProgramData,
}

impl SkMsg {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SK_MSG, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Attaches the program to the given sockmap.
    pub fn attach(&mut self, map: &dyn SocketMap) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let map_fd = map.fd_or_err()?;

        bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT).map_err(|(_, io_error)| {
            ProgramError::SyscallError {
                call: "bpf_prog_attach".to_owned(),
                io_error,
            }
        })?;
        Ok(self
            .data
            .link(ProgAttachLink::new(prog_fd, map_fd, BPF_SK_MSG_VERDICT)))
    }
}
