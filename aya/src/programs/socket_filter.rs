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
        ProgramData, ProgramError, ProgramType, links::FdLink, load_program_without_attach_type,
    },
};

macro_rules! setsockopt_socket_filter {
    ($socket:expr, $option:ident, $value:expr) => {{
        let value = $value;
        let ret = unsafe {
            setsockopt(
                $socket,
                SOL_SOCKET,
                $option as libc::c_int,
                ptr::from_ref(value).cast(),
                size_of_val(value) as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(SocketFilterError::SetsockoptError {
                option: stringify!($option),
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
/// [`SocketFilter`] programs are attached on sockets and can be used to inspect
/// and filter incoming packets.
///
/// Each socket has one filter slot. Attaching a new [`SocketFilter`] replaces
/// the socket's current filter, and detaching clears that current filter
/// regardless of which program installed it. Aya therefore does not expose a
/// link-style attachment handle for [`SocketFilter`] or automatically track
/// socket filter attachments for cleanup. Dropping [`SocketFilter`] or
/// [`crate::Ebpf`] does not detach the filter; call [`SocketFilter::detach`]
/// explicitly when you want to remove it, or close the socket.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
/// `BPF_PROG_TYPE_SOCKET_FILTER` and `SO_ATTACH_BPF` are present in Linux
/// v3.19:
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

    /// Attaches the filter on the given socket.
    ///
    /// If the socket already has a filter attached, attaching again replaces
    /// the current filter instead of returning an already-attached error. This
    /// follows the kernel model: each socket has one filter slot and cannot run
    /// multiple socket filters together. The kernel detach API also clears the
    /// socket's current filter slot; it cannot detach a specific program
    /// attachment. For that reason, Aya does not provide link-level RAII
    /// semantics for socket filters. Dropping [`SocketFilter`] or [`crate::Ebpf`]
    /// does not detach the filter. Call [`SocketFilter::detach`] explicitly when
    /// you want to remove it, or close the socket.
    pub fn attach<T: AsFd>(&self, socket: T) -> Result<(), ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd().as_raw_fd();
        let socket = socket.as_fd().as_raw_fd();

        setsockopt_socket_filter!(socket, SO_ATTACH_BPF, &prog_fd)?;
        Ok(())
    }

    /// Detaches the current filter from the given socket.
    ///
    /// Detaching clears the socket's current filter slot, regardless of which
    /// program was used to attach that filter. Unlike [`SocketFilter::attach`],
    /// this operation does not require the program to remain loaded in this
    /// process. If another filter replaced this program on the same socket,
    /// detaching will remove that replacement filter.
    pub fn detach<T: AsFd>(socket: T) -> Result<(), ProgramError> {
        let socket = socket.as_fd().as_raw_fd();

        // `SO_DETACH_BPF` is an alias for `SO_DETACH_FILTER`; Linux's
        // `sk_setsockopt()` requires an `int` optval, but the detach branch only
        // calls `sk_detach_filter(sk)` and does not use a program fd:
        // https://github.com/torvalds/linux/blob/v6.9/net/core/sock.c#L1413-L1414
        let dummy: libc::c_int = 0;
        setsockopt_socket_filter!(socket, SO_DETACH_BPF, &dummy)?;
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
