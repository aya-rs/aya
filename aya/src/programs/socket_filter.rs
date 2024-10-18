//! Socket filter programs.
use std::{
    io, mem,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use libc::{setsockopt, SOL_SOCKET};

use crate::{
    errors::{InternalLinkError, LinkError},
    generated::{bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER, SO_ATTACH_BPF, SO_DETACH_BPF},
    programs::{load_program, Link, ProgramData, ProgramError},
};

/// A program used to inspect and filter incoming packets on a socket.
///
/// [`SocketFilter`] programs are attached on sockets and can be used to inspect
/// and filter incoming packets.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.0.
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
/// use std::net::TcpStream;
/// use aya::programs::SocketFilter;
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// let prog: &mut SocketFilter = bpf.program_mut("filter_packets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&client)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCKET_FILTER")]
pub struct SocketFilter {
    pub(crate) data: ProgramData<SocketFilterLink>,
}

impl SocketFilter {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_SOCKET_FILTER, &mut self.data)
    }

    /// Attaches the filter on the given socket.
    ///
    /// The returned value can be used to detach from the socket, see [SocketFilter::detach].
    pub fn attach<T: AsFd>(&mut self, socket: T) -> Result<SocketFilterLinkId, LinkError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let prog_fd = prog_fd.as_raw_fd();
        let socket = socket.as_fd();
        let socket = socket.as_raw_fd();

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_BPF as i32,
                &prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(InternalLinkError::SoAttachEbpf {
                io_error: io::Error::last_os_error(),
            }
            .into());
        }

        self.data.links.insert(SocketFilterLink { socket, prog_fd })
    }

    /// Detaches the program.
    ///
    /// See [SocketFilter::attach].
    pub fn detach(&mut self, link_id: SocketFilterLinkId) -> Result<(), LinkError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(
        &mut self,
        link_id: SocketFilterLinkId,
    ) -> Result<SocketFilterLink, LinkError> {
        self.data.take_link(link_id)
    }
}

/// The type returned by [SocketFilter::attach]. Can be passed to [SocketFilter::detach].
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct SocketFilterLinkId(RawFd, RawFd);

/// A SocketFilter Link
#[derive(Debug)]
pub struct SocketFilterLink {
    socket: RawFd,
    prog_fd: RawFd,
}

impl Link for SocketFilterLink {
    type Id = SocketFilterLinkId;

    fn id(&self) -> Self::Id {
        SocketFilterLinkId(self.socket, self.prog_fd)
    }

    fn detach(self) -> Result<(), LinkError> {
        unsafe {
            setsockopt(
                self.socket,
                SOL_SOCKET,
                SO_DETACH_BPF as i32,
                &self.prog_fd as *const _ as *const _,
                mem::size_of::<RawFd>() as u32,
            );
        }
        Ok(())
    }
}
