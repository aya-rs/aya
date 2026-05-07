//! Socket filter programs.
use std::{
    io,
    os::fd::{AsFd, AsRawFd as _, OwnedFd, RawFd},
};

use aya_obj::generated::{
    SO_ATTACH_BPF, SO_DETACH_BPF, bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
};
use libc::{SOL_SOCKET, setsockopt};
use thiserror::Error;

use crate::programs::{
    Link, ProgramData, ProgramError, ProgramType, define_link_wrapper, id_as_key,
    load_program_without_attach_type,
};

/// The type returned when attaching a [`SocketFilter`] fails.
#[derive(Debug, Error)]
pub enum SocketFilterError {
    /// Setting the `SO_ATTACH_BPF` socket option failed.
    #[error("setsockopt SO_ATTACH_BPF failed")]
    SoAttachEbpfError {
        /// original [`io::Error`]
        #[source]
        io_error: io::Error,
    },
}

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
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SocketFilter;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_SOCKET_FILTER, data)
    }

    /// Attaches the filter on the given socket.
    ///
    /// The returned value can be used to detach from the socket, see [`SocketFilter::detach`].
    /// To detach on drop, pass it to [`SocketFilter::take_link`] and drop the returned
    /// [`SocketFilterLink`].
    ///
    /// `attach` duplicates the socket file descriptor. The managed link owns that
    /// duplicate and uses it to detach the filter, so the caller does not need to keep
    /// the original file descriptor open for detach. If the link is taken with
    /// [`SocketFilter::take_link`], the returned [`SocketFilterLink`] owns the duplicate
    /// and keeps the socket open until it is detached or dropped.
    pub fn attach<T: AsFd>(&mut self, socket: T) -> Result<SocketFilterLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let prog_fd = prog_fd.as_raw_fd();
        let socket = socket.as_fd();
        let socket_fd = socket.as_raw_fd();
        let link_id = SocketFilterLinkId(SocketFilterLinkIdInner(socket_fd, prog_fd));

        // The kernel allows installing the same socket filter program on the
        // same socket again, but the socket still only has one filter slot.
        // Aya represents that as one link. Use `insert` so duplicates are
        // rejected before the second install reaches the socket; otherwise a
        // rejected RAII link would be dropped and detach the socket's current filter.
        self.data.links.insert(link_id, || {
            // Duplicate the socket fd so detach/drop do not depend on the
            // caller's fd lifetime.
            let socket = socket.try_clone_to_owned()?;
            let ret = unsafe {
                setsockopt(
                    socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_ATTACH_BPF as i32,
                    std::ptr::from_ref(&prog_fd).cast(),
                    size_of_val(&prog_fd) as u32,
                )
            };
            if ret < 0 {
                return Err(SocketFilterError::SoAttachEbpfError {
                    io_error: io::Error::last_os_error(),
                }
                .into());
            }

            Ok(SocketFilterLink::new(SocketFilterLinkInner {
                socket,
                socket_fd,
                prog_fd,
            }))
        })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct SocketFilterLinkIdInner(RawFd, RawFd);

#[derive(Debug)]
struct SocketFilterLinkInner {
    // Used for detach/drop.
    socket: OwnedFd,
    // Used for the link id. This is the caller's fd number, not the
    // duplicate, so duplicate attaches to the same socket still use the same id.
    socket_fd: RawFd,
    prog_fd: RawFd,
}

impl Link for SocketFilterLinkInner {
    type Id = SocketFilterLinkIdInner;

    fn id(&self) -> Self::Id {
        SocketFilterLinkIdInner(self.socket_fd, self.prog_fd)
    }

    fn detach(self) -> Result<(), ProgramError> {
        unsafe {
            setsockopt(
                self.socket.as_raw_fd(),
                SOL_SOCKET,
                SO_DETACH_BPF as i32,
                std::ptr::from_ref(&self.prog_fd).cast(),
                size_of_val(&self.prog_fd) as u32,
            );
        }
        Ok(())
    }
}

id_as_key!(SocketFilterLinkInner, SocketFilterLinkIdInner);

define_link_wrapper!(
    SocketFilterLink,
    SocketFilterLinkId,
    SocketFilterLinkInner,
    SocketFilterLinkIdInner,
    SocketFilter,
);
