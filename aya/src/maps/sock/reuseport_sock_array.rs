//! An array of sockets for SO_REUSEPORT selection.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd as _, AsRawFd, RawFd},
};

use crate::{
    maps::{MapData, MapError, MapFd, MapKeys, check_bounds, check_kv_size, sock::SockMapFd},
    sys::{SyscallError, bpf_map_delete_elem, bpf_map_update_elem},
};

/// An array of sockets that can be shared between eBPF programs and user space.
///
/// `ReusePortSockArray` stores sockets that participate in SO_REUSEPORT groups.
/// eBPF programs of type `BPF_PROG_TYPE_SK_REUSEPORT` can use this map with the
/// `bpf_sk_select_reuseport()` helper to select specific sockets for incoming
/// connections.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::ReusePortSockArray;
/// use aya::programs::SkReuseport;
/// use std::os::fd::{AsRawFd, FromRawFd};
/// use std::net::TcpListener;
/// use libc::{socket, setsockopt, bind, listen, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEPORT, sockaddr_in};
///
/// // Create socket with SO_REUSEPORT enabled
/// let socket_fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
/// let enable = 1i32;
/// unsafe {
///     setsockopt(
///         socket_fd,
///         SOL_SOCKET,
///         SO_REUSEPORT,
///         &enable as *const _ as *const _,
///         std::mem::size_of_val(&enable) as u32,
///     );
/// }
/// 
/// // Bind and listen (setup details omitted for brevity)
/// // ... bind(socket_fd, &addr, addr_len) and listen(socket_fd, backlog) ...
/// let socket = unsafe { TcpListener::from_raw_fd(socket_fd) };
///
/// // Load the socket array map and populate it
/// let mut socket_array: ReusePortSockArray<_> = bpf.take_map("socket_map").unwrap().try_into()?;
/// socket_array.set(0, &socket, 0)?;
///
/// // Load and attach the SK_REUSEPORT program
/// let prog: &mut SkReuseport = bpf.program_mut("select_socket").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&socket)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Complete Setup Example
///
/// This example shows proper SO_REUSEPORT socket group setup:
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::ReusePortSockArray;
/// use aya::programs::SkReuseport;
/// use std::net::TcpListener;
/// use std::os::fd::{AsRawFd, FromRawFd};
/// use libc::{socket, setsockopt, bind, listen, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEPORT, sockaddr_in};
///
/// // Create multiple sockets in SO_REUSEPORT group
/// let port = 8080u16;
/// let addr = sockaddr_in {
///     sin_family: AF_INET as u16,
///     sin_port: port.to_be(),
///     sin_addr: libc::in_addr { s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be() },
///     sin_zero: [0; 8],
/// };
///
/// let enable = 1i32;
/// let mut sockets = Vec::new();
///
/// // Create 4 SO_REUSEPORT sockets
/// for _ in 0..4 {
///     let socket_fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
///     unsafe {
///         // Set SO_REUSEPORT before binding (required for reuseport groups)
///         setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, 
///                   &enable as *const _ as *const _, std::mem::size_of_val(&enable) as u32);
///         bind(socket_fd, &addr as *const _ as *const libc::sockaddr, 
///              std::mem::size_of::<sockaddr_in>() as u32);
///         listen(socket_fd, 1024);
///     }
///     sockets.push(unsafe { TcpListener::from_raw_fd(socket_fd) });
/// }
///
/// // Load and populate the socket array map
/// let mut socket_array: ReusePortSockArray<_> = bpf.take_map("socket_map").unwrap().try_into()?;
/// for (i, socket) in sockets.iter().enumerate() {
///     socket_array.set(i as u32, socket, 0)?;
/// }
///
/// // Load and attach the SK_REUSEPORT program to first socket in group
/// let prog: &mut SkReuseport = bpf.program_mut("load_balancer").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(&sockets[0])?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY")]
pub struct ReusePortSockArray<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> ReusePortSockArray<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, RawFd>(data)?;

        Ok(Self { inner: map })
    }

    /// An iterator over the indices of the array that point to a socket. The iterator item type
    /// is `Result<u32, MapError>`.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }

    /// Returns the map's file descriptor.
    ///
    /// The returned file descriptor can be used with [`SkReuseport`](crate::programs::SkReuseport) programs.
    pub fn fd(&self) -> &SockMapFd {
        let fd: &MapFd = self.inner.borrow().fd();
        // TODO(https://github.com/rust-lang/rfcs/issues/3066): avoid this unsafe.
        // SAFETY: `SockMapFd` is #[repr(transparent)] over `MapFd`.
        unsafe { std::mem::transmute(fd) }
    }
}

impl<T: BorrowMut<MapData>> ReusePortSockArray<T> {
    /// Stores a socket into the map at the given index.
    ///
    /// The socket will be available for selection by `bpf_sk_select_reuseport()` helper
    /// using the provided index.
    pub fn set<I: AsRawFd>(&mut self, index: u32, socket: &I, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        let fd = data.fd().as_fd();
        check_bounds(data, index)?;
        bpf_map_update_elem(fd, Some(&index), &socket.as_raw_fd(), flags)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
            .map_err(Into::into)
    }

    /// Removes the socket stored at `index` from the map.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        let fd = data.fd().as_fd();
        check_bounds(data, *index)?;
        bpf_map_delete_elem(fd, index)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_delete_elem",
                io_error,
            })
            .map_err(Into::into)
    }
}