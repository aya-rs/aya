//! Socket load balancing with `SO_REUSEPORT`.
use std::{
    io,
    os::fd::{AsFd, AsRawFd as _},
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

// `libc` exposes `SO_ATTACH_REUSEPORT_EBPF`, but
// `SO_DETACH_REUSEPORT_BPF` is still missing on some Linux architectures.
// Keep both local definitions together rather than mixing constant sources.
// TODO: Consider sourcing these from per-arch eBPF bindings instead of
// hardcoding asm-generic values here.
const SO_ATTACH_REUSEPORT_EBPF: libc::c_int = 52;
const SO_DETACH_REUSEPORT_BPF: libc::c_int = 68;

/// Error returned by reuseport socket option operations.
#[derive(Debug, Error)]
pub enum SkReuseportError {
    /// Setting a reuseport socket option failed.
    #[error("setsockopt {option} failed")]
    SetsockoptError {
        /// Socket option passed to `setsockopt`.
        option: &'static str,
        /// Underlying OS error.
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
/// // `SO_REUSEPORT` must be set before `bind(2)`. The kernel only adds a
/// // socket to a reuseport group during bind:
/// // - Bind requires both the existing and new sockets to have
/// //   `SO_REUSEPORT` set; if either side lacks it, bind fails with
/// //   `EADDRINUSE`.
/// // - Setting `SO_REUSEPORT` after bind is silently ignored; the socket is
/// //   not added to any reuseport group.
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

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_SK_REUSEPORT, *attach_type, data)
    }

    /// Attaches the program to the `SO_REUSEPORT` group containing `socket`.
    ///
    /// The socket must already be configured with `SO_REUSEPORT`.
    /// Returns `EINVAL` if it is not
    ///
    /// Attaching through any socket in a reuseport group replaces the program
    /// used by the entire group. Aya does not return a link handle for this
    /// operation. Dropping the program object does not detach it; call
    /// [`SkReuseport::detach`] with any socket from the same group to remove it
    /// again, or close all sockets in the group.
    pub fn attach<T: AsFd>(&mut self, socket: T) -> Result<(), ProgramError> {
        let prog_fd = self.fd()?.as_fd().as_raw_fd();
        let socket = socket.as_fd().as_raw_fd();

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_REUSEPORT_EBPF,
                ptr::from_ref(&prog_fd).cast(),
                size_of_val(&prog_fd) as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(SkReuseportError::SetsockoptError {
                option: "SO_ATTACH_REUSEPORT_EBPF",
                io_error: io::Error::last_os_error(),
            }
            .into())
        } else {
            Ok(())
        }
    }

    /// Detaches the current reuseport program from the `SO_REUSEPORT` group
    /// containing `socket`.
    ///
    /// Detaching through any socket in a reuseport group removes the program
    /// from the entire group, regardless of which socket in that group was
    /// used to attach it. Unlike [`SkReuseport::attach`], this operation does
    /// not require the program to remain loaded in this process.
    pub fn detach<T: AsFd>(&mut self, socket: T) -> Result<(), ProgramError> {
        let socket = socket.as_fd().as_raw_fd();
        let dummy: libc::c_int = 0;

        // `SO_DETACH_REUSEPORT_BPF` identifies the reuseport group from the
        // socket, so the detach operation does not use this value. However, the
        // generic `SOL_SOCKET` setsockopt path still requires an int-sized,
        // readable optval before it dispatches on the specific sockopt.
        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_DETACH_REUSEPORT_BPF,
                ptr::from_ref(&dummy).cast(),
                size_of_val(&dummy) as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(SkReuseportError::SetsockoptError {
                option: "SO_DETACH_REUSEPORT_BPF",
                io_error: io::Error::last_os_error(),
            }
            .into())
        } else {
            Ok(())
        }
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// `SkReuseport` does not use link-style attachments, so this only
    /// restores access to the pinned program itself.
    ///
    /// Dropping the returned value unloads the local program FD, but does not
    /// detach the program from any `SO_REUSEPORT` group. This will also not
    /// unload the program from the kernel while it remains pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: SkReuseportAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}
