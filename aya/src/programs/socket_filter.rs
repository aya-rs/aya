//! Socket filter programs.
use std::{
    io,
    os::fd::{AsFd, AsRawFd as _},
    path::Path,
    ptr,
};

use aya_obj::generated::{
    SO_ATTACH_BPF, SO_DETACH_BPF, bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER,
};
use libc::{SOL_SOCKET, setsockopt};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        ProgramData, ProgramError, ProgramType, SO_ATTACH_REUSEPORT_EBPF, SO_DETACH_REUSEPORT_BPF,
        links::FdLink, load_program_without_attach_type,
    },
};

macro_rules! setsockopt_socket_filter {
    ($socket:expr, $option:expr, $option_name:expr, $value:expr) => {{
        let value = $value;
        let ret = unsafe {
            setsockopt(
                $socket,
                SOL_SOCKET,
                $option,
                ptr::from_ref(value).cast(),
                size_of_val(value) as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(SocketFilterError::SetsockoptError {
                option: $option_name,
                io_error: io::Error::last_os_error(),
            })
        } else {
            Ok(())
        }
    }};
}

/// The type returned when a [`SocketFilter`] socket option operation fails.
#[derive(Debug, Error)]
pub enum SocketFilterError {
    /// Setting a socket filter socket option failed.
    #[error("setsockopt {option} failed")]
    SetsockoptError {
        /// Socket option passed to `setsockopt`.
        option: &'static str,
        /// Underlying OS error.
        #[source]
        io_error: io::Error,
    },
}

/// A program used to inspect and filter incoming packets on a socket.
///
/// This is a `BPF_PROG_TYPE_SOCKET_FILTER` program attached as a regular
/// socket filter. The same kernel program type can also be attached to
/// `SO_REUSEPORT` groups through [`ReusePortSocketFilter`].
///
/// Since both abstractions use the same libbpf `SEC("socket")` section,
/// converting from [`crate::programs::Program`] with `try_into` selects this
/// abstraction from the caller's requested type rather than from distinct load
/// metadata.
///
/// The return value is interpreted as a packet length: `0` drops the packet, a
/// value greater than or equal to the packet length accepts the whole packet,
/// and a smaller positive value trims the packet to that length.
///
/// Regular socket filters are scoped to one socket. `SO_ATTACH_BPF` writes the
/// socket's `sk->sk_filter` field:
/// <https://github.com/torvalds/linux/blob/v6.9/net/core/filter.c#L1476-L1478>
///
/// Attaching a new program replaces the current program in that slot, and
/// detaching clears the slot regardless of which program installed it. On the
/// same socket, [`SocketFilter`] and [`ReusePortSocketFilter`] use different
/// kernel slots and do not affect each other. For that reason, [`SocketFilter`]
/// does not expose a link-style attachment handle or automatically track
/// attachments for cleanup. Dropping [`SocketFilter`] or [`crate::Ebpf`] does
/// not detach the program; call [`SocketFilter::detach`] explicitly when you
/// want to remove it, or close the socket.
///
/// # Minimum kernel version
///
/// `BPF_PROG_TYPE_SOCKET_FILTER` and `SO_ATTACH_BPF` are present in Linux 3.19:
/// <https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h#L118-L120>
/// <https://github.com/torvalds/linux/blob/v3.19/include/uapi/asm-generic/socket.h#L87-L88>
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
// Invariant: `TryFrom<Program>` casts references between `SocketFilter` and
// `ReusePortSocketFilter`. Keep both types as transparent wrappers around the
// same `ProgramData<FdLink>` field.
#[repr(transparent)]
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCKET_FILTER")]
pub struct SocketFilter {
    pub(crate) data: ProgramData<FdLink>,
}

impl SocketFilter {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SocketFilter;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_SOCKET_FILTER, data)
    }

    /// Attaches the program on the given socket.
    ///
    /// If the socket already has a regular filter attached, attaching again
    /// replaces the current filter instead of returning an already-attached
    /// error.
    pub fn attach<T: AsFd>(&self, socket: T) -> Result<(), ProgramError> {
        let prog_fd = self.fd()?.as_fd().as_raw_fd();
        let socket = socket.as_fd().as_raw_fd();

        setsockopt_socket_filter!(
            socket,
            SO_ATTACH_BPF as libc::c_int,
            "SO_ATTACH_BPF",
            &prog_fd
        )?;
        Ok(())
    }

    /// Detaches the current regular socket filter from the given socket.
    ///
    /// Detaching clears the socket's current filter slot, regardless of which
    /// program was used to attach that filter. If another filter replaced this
    /// program on the same socket, detaching will remove that replacement
    /// filter. It does not affect the socket's reuseport group selector.
    ///
    /// Unlike [`SocketFilter::attach`], this operation does not require the
    /// program to remain loaded in this process.
    pub fn detach<T: AsFd>(socket: T) -> Result<(), ProgramError> {
        let socket = socket.as_fd().as_raw_fd();

        // `SO_DETACH_BPF` is an alias for `SO_DETACH_FILTER`; Linux's
        // `sk_setsockopt()` requires an `int` optval, but the detach branch only
        // calls `sk_detach_filter(sk)` and does not use a program fd.
        // The generic `SOL_SOCKET` path still requires an int-sized optval
        // before dispatching on the specific sockopt.
        // https://github.com/torvalds/linux/blob/v6.9/net/core/sock.c#L1409-L1414
        let dummy: libc::c_int = 0;

        setsockopt_socket_filter!(
            socket,
            SO_DETACH_BPF as libc::c_int,
            "SO_DETACH_BPF",
            &dummy
        )?;
        Ok(())
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// `SocketFilter` does not use link-style attachments, so this only
    /// restores access to the pinned program itself.
    ///
    /// Dropping the returned value unloads the local program FD, but does not
    /// detach the filter from any socket. This will also not unload the program
    /// from the kernel while it remains pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data })
    }
}

/// A socket filter program used as a `SO_REUSEPORT` group selector.
///
/// This is a `BPF_PROG_TYPE_SOCKET_FILTER` program attached through
/// `SO_ATTACH_REUSEPORT_EBPF`. The same kernel program type can also be
/// attached as a regular socket filter through [`SocketFilter`].
///
/// Since both abstractions use the same libbpf `SEC("socket")` section,
/// converting from [`crate::programs::Program`] with `try_into` selects this
/// abstraction from the caller's requested type rather than from distinct load
/// metadata.
///
/// The program return value is interpreted as the selected socket index in the
/// reuseport group. The socket must already be configured with `SO_REUSEPORT`.
///
/// Regular [`SocketFilter`] programs and [`ReusePortSocketFilter`] programs use
/// separate kernel-managed slots. Regular filters are scoped to one socket;
/// reuseport selectors are scoped to the whole `SO_REUSEPORT` group.
/// `SO_ATTACH_REUSEPORT_EBPF` writes the group's `reuse->prog` field:
/// <https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L706-L708>
///
/// Attaching or detaching one type does not affect the other. For reuseport
/// groups, attaching through any socket in the group replaces the program used
/// by the entire group, and detaching through any socket in the group clears
/// the selector. [`ReusePortSocketFilter`] does not expose a link-style
/// attachment handle or automatically track group attachments for cleanup.
/// Dropping [`ReusePortSocketFilter`] or [`crate::Ebpf`] does not detach the
/// program; call [`ReusePortSocketFilter::detach`] explicitly when you want to
/// remove it, or close all sockets in the group so the group itself is
/// destroyed.
///
/// [`SkReuseport`](crate::programs::SkReuseport) is the purpose-built program
/// type for `SO_REUSEPORT` selection on newer kernels; `ReusePortSocketFilter`
/// is useful when you need the older `SO_ATTACH_REUSEPORT_EBPF` socket-filter
/// path or want to attach an existing `SEC("socket")` program to a reuseport
/// group.
///
/// # Minimum kernel version
///
/// `SO_ATTACH_REUSEPORT_EBPF` can attach socket filter programs to UDP
/// `SO_REUSEPORT` groups starting in Linux 4.5 and TCP groups starting in
/// Linux 4.6:
/// <https://github.com/torvalds/linux/blob/v4.5/net/ipv4/udp.c#L521-L522>
/// <https://github.com/torvalds/linux/blob/v4.6/net/ipv4/inet_hashtables.c#L237-L239>
///
/// `SO_DETACH_REUSEPORT_BPF` is handled starting in Linux 5.3:
/// <https://github.com/torvalds/linux/blob/v5.3/net/core/sock.c#L1042-L1044>
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
/// use aya::programs::ReusePortSocketFilter;
/// use nix::sys::socket::{
///     AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, bind, listen, setsockopt,
///     socket, sockopt::ReusePort,
/// };
///
/// // `SO_REUSEPORT` must be set before `bind(2)`. `std::net::TcpListener`
/// // does not expose that pre-bind socket setup step, so this example uses
/// // `nix` to create and configure the socket directly.
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
/// let program: &mut ReusePortSocketFilter = bpf.program_mut("select_socket").unwrap().try_into()?;
/// program.load()?;
/// program.attach(&listener)?;
/// # }
/// # Ok::<(), Error>(())
/// ```
// Invariant: `TryFrom<Program>` casts references between `SocketFilter` and
// `ReusePortSocketFilter`. Keep both types as transparent wrappers around the
// same `ProgramData<FdLink>` field.
#[repr(transparent)]
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_SOCKET_FILTER")]
pub struct ReusePortSocketFilter {
    pub(crate) data: ProgramData<FdLink>,
}

impl ReusePortSocketFilter {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::SocketFilter;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_SOCKET_FILTER, data)
    }

    /// Attaches the program as a `SO_REUSEPORT` selector.
    ///
    /// Attaching through any socket in the group replaces the program used by
    /// the entire group.
    pub fn attach<T: AsFd>(&self, socket: T) -> Result<(), ProgramError> {
        let prog_fd = self.fd()?.as_fd().as_raw_fd();
        let socket = socket.as_fd().as_raw_fd();

        setsockopt_socket_filter!(
            socket,
            SO_ATTACH_REUSEPORT_EBPF,
            "SO_ATTACH_REUSEPORT_EBPF",
            &prog_fd
        )?;
        Ok(())
    }

    /// Detaches the current reuseport selector from the socket's group.
    ///
    /// Detaching through any socket in a reuseport group removes the program
    /// from the entire group, regardless of which socket in that group was used
    /// to attach it. Detaching a reuseport selector from a socket that is not
    /// in a reuseport group returns `EINVAL`. It does not affect regular
    /// filters attached to individual sockets in the group.
    pub fn detach<T: AsFd>(socket: T) -> Result<(), ProgramError> {
        let socket = socket.as_fd().as_raw_fd();

        // `SO_DETACH_REUSEPORT_BPF` identifies the target group from the
        // socket. The generic `SOL_SOCKET` path still requires an int-sized
        // optval before dispatching on the specific sockopt.
        // https://github.com/torvalds/linux/blob/v6.9/net/core/sock.c#L1409-L1414
        let dummy: libc::c_int = 0;

        setsockopt_socket_filter!(
            socket,
            SO_DETACH_REUSEPORT_BPF,
            "SO_DETACH_REUSEPORT_BPF",
            &dummy
        )?;
        Ok(())
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// `ReusePortSocketFilter` does not use link-style attachments, so this
    /// only restores access to the pinned program itself.
    ///
    /// Dropping the returned value unloads the local program FD, but does not
    /// detach the selector from any reuseport group. This will also not unload
    /// the program from the kernel while it remains pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data })
    }
}
