//! Socket load balancing with `SO_REUSEPORT`.
use std::{
    io,
    os::fd::{AsFd, AsRawFd as _, RawFd},
    path::Path,
    ptr,
};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_SK_REUSEPORT;
pub use aya_obj::programs::SkReuseportAttachType;
use libc::{SOL_SOCKET, setsockopt};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        ProgramData, ProgramError, ProgramType, links::FdLink, load_program_with_attach_type,
    },
};

const SO_ATTACH_REUSEPORT_EBPF: libc::c_int = 52;
const SO_DETACH_REUSEPORT_BPF: libc::c_int = 68;

/// The type returned when attaching a [`SkReuseport`] fails.
#[derive(Debug, Error)]
pub enum SkReuseportError {
    /// Setting the `SO_ATTACH_REUSEPORT_EBPF` socket option failed.
    #[error("setsockopt SO_ATTACH_REUSEPORT_EBPF failed")]
    SoAttachReuseportEbpfError {
        /// original [`io::Error`]
        #[source]
        io_error: io::Error,
    },

    /// Setting the `SO_DETACH_REUSEPORT_BPF` socket option failed.
    #[error("setsockopt SO_DETACH_REUSEPORT_BPF failed")]
    SoDetachReuseportBpfError {
        /// original [`io::Error`]
        #[source]
        io_error: io::Error,
    },
}

/// A program used to select a socket within a `SO_REUSEPORT` group.
///
/// [`SkReuseport`] programs are attached to sockets with `SO_REUSEPORT` set to
/// provide programmable socket selection when multiple sockets are listening
/// on the same port. The program decides which socket in the reuseport group
/// should handle an incoming connection or packet.
///
/// Attaching or detaching through any socket in the group affects the entire
/// `SO_REUSEPORT` group. Aya therefore does not expose a link-style attachment
/// handle for [`SkReuseport`] or automatically track group attachments for
/// cleanup. Dropping [`SkReuseport`] or [`crate::Ebpf`] does not detach the
/// program from the group; call [`SkReuseport::detach`] explicitly when you
/// want to remove it, or close all sockets in the reuseport group so the group
/// itself is destroyed.
///
/// This program type is only supported on Linux hosts. On non-Linux hosts the
/// Linux-specific `SkReuseport` management APIs are not available.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
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
/// use std::{
///     io,
///     net::{Ipv4Addr, SocketAddrV4, TcpListener},
///     os::fd::AsRawFd,
/// };
///
/// use aya::programs::SkReuseport;
/// use nix::sys::socket::{
///     AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, bind, listen, setsockopt,
///     socket, sockopt::ReusePort,
/// };
///
/// // `SO_REUSEPORT` must be enabled after `socket(2)` and before `bind(2)`.
/// // `std::net::TcpListener` does not expose that pre-bind socket setup step,
/// // so this example uses `nix` to create and configure the socket directly.
/// fn reuseport_listener(port: u16) -> io::Result<TcpListener> {
///     let fd = socket(
///         AddressFamily::Inet,
///         SockType::Stream,
///         SockFlag::empty(),
///         None,
///     )
///     .map_err(io::Error::other)?;
///
///     setsockopt(&fd, ReusePort, &true).map_err(io::Error::other)?;
///
///     let addr = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
///     bind(fd.as_raw_fd(), &addr).map_err(io::Error::other)?;
///     listen(&fd, Backlog::MAXCONN).map_err(io::Error::other)?;
///
///     Ok(TcpListener::from(fd))
/// }
///
/// # #[cfg(target_os = "linux")] {
/// let listener = reuseport_listener(8080)?;
/// let program: &mut SkReuseport = bpf.program_mut("select_socket").unwrap().try_into()?;
/// program.load()?;
/// program.attach(&listener)?;
/// # }
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SK_REUSEPORT")]
pub struct SkReuseport {
    pub(crate) data: ProgramData<FdLink>,
    pub(crate) attach_type: SkReuseportAttachType,
}

impl SkReuseport {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SkReuseport;

    #[inline]
    fn set_reuseport_sockopt<T: AsFd>(
        &self,
        socket: T,
        sockopt: libc::c_int,
        map_err: fn(io::Error) -> SkReuseportError,
    ) -> Result<(), ProgramError> {
        let socket = socket.as_fd().as_raw_fd();
        let prog_fd = self.fd()?.as_fd().as_raw_fd();

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                sockopt,
                ptr::from_ref(&prog_fd).cast(),
                size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(map_err(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_SK_REUSEPORT, *attach_type, data)
    }

    /// Attaches the program to the `SO_REUSEPORT` group containing `socket`.
    ///
    /// The socket must already be configured with `SO_REUSEPORT`.
    ///
    /// Attaching through any socket in a reuseport group replaces the program
    /// used by the entire group. Aya does not return a link handle for this
    /// operation. Dropping the program object does not detach it; call
    /// [`SkReuseport::detach`] with any socket from the same group to remove it
    /// again, or close all sockets in the group.
    pub fn attach<T: AsFd>(&self, socket: T) -> Result<(), ProgramError> {
        self.set_reuseport_sockopt(socket, SO_ATTACH_REUSEPORT_EBPF, |io_error| {
            SkReuseportError::SoAttachReuseportEbpfError { io_error }
        })
    }

    /// Detaches the current reuseport program from the `SO_REUSEPORT` group
    /// containing `socket`.
    ///
    /// Detaching through any socket in a reuseport group removes the program
    /// from the entire group, regardless of which socket in that group was
    /// used to attach it.
    pub fn detach<T: AsFd>(&self, socket: T) -> Result<(), ProgramError> {
        self.set_reuseport_sockopt(socket, SO_DETACH_REUSEPORT_BPF, |io_error| {
            SkReuseportError::SoDetachReuseportBpfError { io_error }
        })
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: SkReuseportAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}
