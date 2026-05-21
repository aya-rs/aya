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

/// How a [`SocketFilter`] program should be attached to a socket.
#[derive(Clone, Copy, Debug)]
pub enum SocketFilterAttachType {
    /// Attach the program as a regular socket filter with `SO_ATTACH_BPF`.
    SocketFilter,
    /// Attach the program as a `SO_REUSEPORT` selector with
    /// `SO_ATTACH_REUSEPORT_EBPF`.
    ReusePort,
}

impl SocketFilterAttachType {
    const fn attach_option(self) -> (libc::c_int, &'static str) {
        match self {
            Self::SocketFilter => (SO_ATTACH_BPF as libc::c_int, "SO_ATTACH_BPF"),
            Self::ReusePort => (SO_ATTACH_REUSEPORT_EBPF, "SO_ATTACH_REUSEPORT_EBPF"),
        }
    }

    const fn detach_option(self) -> (libc::c_int, &'static str) {
        match self {
            Self::SocketFilter => (SO_DETACH_BPF as libc::c_int, "SO_DETACH_BPF"),
            Self::ReusePort => (SO_DETACH_REUSEPORT_BPF, "SO_DETACH_REUSEPORT_BPF"),
        }
    }
}

/// A program used to inspect and filter incoming packets on a socket.
///
/// [`SocketFilter`] programs can be attached as regular socket filters with
/// [`SocketFilterAttachType::SocketFilter`]. In that mode, the return value is
/// interpreted as a packet length: `0` drops the packet, a value greater than
/// or equal to the packet length accepts the whole packet, and a smaller
/// positive value trims the packet to that length.
///
/// They can also be attached to `SO_REUSEPORT` groups with
/// [`SocketFilterAttachType::ReusePort`]. In that mode, the return value is
/// interpreted as the selected socket index in the reuseport group.
///
/// The two attachment types use separate kernel-managed slots. Regular filters
/// are scoped to one socket; reuseport selectors are scoped to the whole
/// `SO_REUSEPORT` group. The two attach paths write different kernel fields:
/// `SO_ATTACH_BPF` writes `sk->sk_filter`, while
/// `SO_ATTACH_REUSEPORT_EBPF` writes `reuse->prog`.
/// <https://github.com/torvalds/linux/blob/v6.9/net/core/filter.c#L1476-L1478>
/// <https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L706-L708>
///
/// Attaching or detaching one type does not affect the other. Attaching a new
/// program for the same type replaces the current program in that slot, and
/// detaching clears the slot regardless of which program installed it. For
/// that reason, [`SocketFilter`] does not expose a link-style attachment handle
/// or automatically track these attachments for cleanup. Dropping
/// [`SocketFilter`] or [`crate::Ebpf`] does not detach the program; call
/// [`SocketFilter::detach`] explicitly when you want to remove it, or close the
/// socket.
///
/// # Minimum kernel version
///
/// `BPF_PROG_TYPE_SOCKET_FILTER` and `SO_ATTACH_BPF` are present in Linux 3.19:
/// <https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h#L118-L120>
/// <https://github.com/torvalds/linux/blob/v3.19/include/uapi/asm-generic/socket.h#L87-L88>
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
/// use std::net::TcpStream;
/// use aya::programs::{SocketFilter, SocketFilterAttachType};
///
/// let mut client = TcpStream::connect("127.0.0.1:1234")?;
/// let prog: &mut SocketFilter = bpf.program_mut("filter_packets").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&client, SocketFilterAttachType::SocketFilter)?;
/// # Ok::<(), Error>(())
/// ```
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
    /// [`SocketFilterAttachType::SocketFilter`] attaches the program as a
    /// regular socket filter. If the socket already has a regular filter
    /// attached, attaching again replaces the current filter instead of
    /// returning an already-attached error.
    ///
    /// [`SocketFilterAttachType::ReusePort`] attaches the program as a
    /// `SO_REUSEPORT` selector for the reuseport group containing `socket`.
    /// The socket must already be configured with `SO_REUSEPORT`.
    ///
    /// For reuseport groups, attaching through any socket in the group replaces
    /// the program used by the entire group.
    pub fn attach<T: AsFd>(
        &self,
        socket: T,
        attach_type: SocketFilterAttachType,
    ) -> Result<(), ProgramError> {
        let prog_fd = self.fd()?.as_fd().as_raw_fd();
        let socket = socket.as_fd().as_raw_fd();
        let (option, option_name) = attach_type.attach_option();

        setsockopt_socket_filter!(socket, option, option_name, &prog_fd)?;
        Ok(())
    }

    /// Detaches the current program for `attach_type` from the given socket.
    ///
    /// For [`SocketFilterAttachType::SocketFilter`], detaching clears the socket's
    /// current filter slot, regardless of which program was used to attach that
    /// filter. If another filter replaced this program on the same socket,
    /// detaching will remove that replacement filter. It does not affect the
    /// socket's reuseport group selector.
    ///
    /// For [`SocketFilterAttachType::ReusePort`], detaching through any socket
    /// in a reuseport group removes the program from the entire group,
    /// regardless of which socket in that group was used to attach it.
    /// `SO_DETACH_REUSEPORT_BPF` is available on Linux 5.3 and later. It does
    /// not affect regular filters attached to individual sockets in the group.
    ///
    /// Detaching an attachment type whose slot is empty returns the underlying
    /// OS error, usually `ENOENT`. Detaching a reuseport selector from a socket
    /// that is not in a reuseport group returns `EINVAL`.
    ///
    /// Unlike [`SocketFilter::attach`], this operation does not require the
    /// program to remain loaded in this process.
    pub fn detach<T: AsFd>(
        socket: T,
        attach_type: SocketFilterAttachType,
    ) -> Result<(), ProgramError> {
        let socket = socket.as_fd().as_raw_fd();

        // `SO_DETACH_BPF` is an alias for `SO_DETACH_FILTER`; Linux's
        // `sk_setsockopt()` requires an `int` optval, but the detach branch only
        // calls `sk_detach_filter(sk)` and does not use a program fd.
        // `SO_DETACH_REUSEPORT_BPF` similarly identifies the target group from
        // the socket. The generic `SOL_SOCKET` path still requires an int-sized
        // optval before dispatching on the specific sockopt.
        // https://github.com/torvalds/linux/blob/v6.9/net/core/sock.c#L1409-L1414
        let dummy: libc::c_int = 0;
        let (option, option_name) = attach_type.detach_option();

        setsockopt_socket_filter!(socket, option, option_name, &dummy)?;
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
