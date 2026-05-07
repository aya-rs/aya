//! Socket filter programs.
use std::{
    io,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd},
    ptr,
};

use aya_obj::generated::{
    SO_ATTACH_BPF, SO_DETACH_BPF, bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
};
use libc::{SOL_SOCKET, setsockopt};
use thiserror::Error;

use crate::{
    programs::{
        Link, ProgramData, ProgramError, ProgramType, define_link_wrapper, id_as_key,
        load_program_without_attach_type,
    },
    sys::SyscallError,
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
        let socket_id = socket_identity(socket)?;
        let link_id = SocketFilterLinkId(SocketFilterLinkIdInner { socket_id });

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
                    SO_ATTACH_BPF as libc::c_int,
                    ptr::from_ref(&prog_fd).cast(),
                    size_of_val(&prog_fd) as libc::socklen_t,
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
                socket_id,
            }))
        })
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct SocketFilterLinkIdInner {
    socket_id: SocketIdentity,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct SocketIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

fn socket_identity(socket: BorrowedFd<'_>) -> Result<SocketIdentity, ProgramError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let ret = unsafe { libc::fstat(socket.as_raw_fd(), stat.as_mut_ptr()) };
    if ret < 0 {
        return Err(SyscallError {
            call: "fstat",
            io_error: io::Error::last_os_error(),
        }
        .into());
    }

    let stat = unsafe { stat.assume_init() };
    Ok(SocketIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[derive(Debug)]
struct SocketFilterLinkInner {
    // Used for detach/drop.
    socket: OwnedFd,
    // Used for the link id, so duplicate fds for the same socket share one id.
    socket_id: SocketIdentity,
}

impl Link for SocketFilterLinkInner {
    type Id = SocketFilterLinkIdInner;

    fn id(&self) -> Self::Id {
        SocketFilterLinkIdInner {
            socket_id: self.socket_id,
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        // `SO_DETACH_BPF` is an alias for `SO_DETACH_FILTER`; Linux's
        // `sk_setsockopt()` requires an `int` optval, but the detach branch only
        // calls `sk_detach_filter(sk)` and does not use a program fd:
        // https://github.com/torvalds/linux/blob/v6.9/net/core/sock.c#L1413-L1414
        let dummy: libc::c_int = 0;
        unsafe {
            setsockopt(
                self.socket.as_raw_fd(),
                SOL_SOCKET,
                SO_DETACH_BPF as libc::c_int,
                ptr::from_ref(&dummy).cast(),
                size_of_val(&dummy) as libc::socklen_t,
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
