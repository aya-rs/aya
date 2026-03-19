//! Socket load balancing with `SO_REUSEPORT`.
use std::io;
#[cfg(target_os = "linux")]
use std::{
    os::fd::{AsFd, AsRawFd as _, RawFd},
    ptr,
};

#[cfg(target_os = "linux")]
use aya_obj::generated::{
    bpf_attach_type::BPF_SK_REUSEPORT_SELECT, bpf_prog_type::BPF_PROG_TYPE_SK_REUSEPORT,
};
#[cfg(target_os = "linux")]
use libc::{SOL_SOCKET, setsockopt};
use thiserror::Error;

use crate::programs::{ProgramData, ProgramError, ProgramType, links::FdLink, load_program};

#[cfg(target_os = "linux")]
const SO_ATTACH_REUSEPORT_EBPF: libc::c_int = 52;
#[cfg(target_os = "linux")]
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
///     mem::{size_of, size_of_val},
///     net::TcpListener,
///     os::fd::{AsRawFd, FromRawFd, OwnedFd},
///     ptr,
/// };
///
/// use aya::programs::SkReuseport;
/// use libc::{
///     AF_INET, SO_REUSEPORT, SOCK_STREAM, SOL_SOCKET, bind, in_addr, listen, setsockopt,
///     sockaddr, sockaddr_in, socket, socklen_t,
/// };
///
/// // `SO_REUSEPORT` must be enabled after `socket(2)` and before `bind(2)`.
/// // `TcpListener::bind()` does not expose that pre-bind socket setup step,
/// // so this example uses `libc` to configure the socket before binding it.
/// fn reuseport_listener(port: u16) -> io::Result<TcpListener> {
///     let fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
///     if fd < 0 {
///         return Err(io::Error::last_os_error());
///     }
///
///     let fd = unsafe { OwnedFd::from_raw_fd(fd) };
///     let enable = 1i32;
///     if unsafe {
///         setsockopt(
///             fd.as_raw_fd(),
///             SOL_SOCKET,
///             SO_REUSEPORT,
///             ptr::from_ref(&enable).cast(),
///             size_of_val(&enable) as socklen_t,
///         )
///     } < 0
///     {
///         return Err(io::Error::last_os_error());
///     }
///
///     let addr = sockaddr_in {
///         sin_family: AF_INET as u16,
///         sin_port: port.to_be(),
///         sin_addr: in_addr {
///             s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
///         },
///         sin_zero: [0; 8],
///     };
///     if unsafe {
///         bind(
///             fd.as_raw_fd(),
///             ptr::from_ref(&addr).cast::<sockaddr>(),
///             size_of::<sockaddr_in>() as socklen_t,
///         )
///     } < 0
///     {
///         return Err(io::Error::last_os_error());
///     }
///     if unsafe { listen(fd.as_raw_fd(), 1024) } < 0 {
///         return Err(io::Error::last_os_error());
///     }
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
}

impl SkReuseport {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SkReuseport;

    #[cfg(target_os = "linux")]
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        self.data
            .expected_attach_type
            .get_or_insert(BPF_SK_REUSEPORT_SELECT);
        load_program(BPF_PROG_TYPE_SK_REUSEPORT, &mut self.data)
    }

    #[cfg(target_os = "linux")]
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
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let prog_fd = prog_fd.as_raw_fd();
        let socket = socket.as_fd();
        let socket = socket.as_raw_fd();

        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_ATTACH_REUSEPORT_EBPF,
                ptr::from_ref(&prog_fd).cast(),
                size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(SkReuseportError::SoAttachReuseportEbpfError {
                io_error: io::Error::last_os_error(),
            }
            .into());
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// Detaches the current reuseport program from the `SO_REUSEPORT` group
    /// containing `socket`.
    ///
    /// Detaching through any socket in a reuseport group removes the program
    /// from the entire group, regardless of which socket in that group was
    /// used to attach it.
    pub fn detach<T: AsFd>(&self, socket: T) -> Result<(), ProgramError> {
        let socket = socket.as_fd();
        let socket = socket.as_raw_fd();
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let prog_fd = prog_fd.as_raw_fd();
        let ret = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                SO_DETACH_REUSEPORT_BPF,
                ptr::from_ref(&prog_fd).cast(),
                size_of::<RawFd>() as u32,
            )
        };
        if ret < 0 {
            return Err(SkReuseportError::SoDetachReuseportBpfError {
                io_error: io::Error::last_os_error(),
            }
            .into());
        }
        Ok(())
    }
}
