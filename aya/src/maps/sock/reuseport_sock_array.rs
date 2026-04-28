//! An array of sockets for `SO_REUSEPORT` selection.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd as _, AsRawFd, RawFd},
};

use crate::{
    maps::{MapData, MapError, MapKeys, check_bounds, check_kv_size},
    sys::{SyscallError, bpf_map_delete_elem, bpf_map_update_elem},
};

/// An array of sockets that can be shared between eBPF programs and user space.
///
/// `ReusePortSockArray` stores sockets that participate in `SO_REUSEPORT` groups.
/// `BPF_PROG_TYPE_SK_REUSEPORT` programs can use sockets stored in this map to
/// steer incoming packets to specific listeners within a reuseport group.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
///
/// # Examples
///
/// Populate the map with sockets from the same `SO_REUSEPORT` group. For a
/// complete listener setup example, see
/// [`SkReuseport`](crate::programs::SkReuseport).
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// # use std::{io, net::TcpListener};
///
/// use aya::maps::ReusePortSockArray;
///
/// # fn reuseport_listener(_port: u16) -> io::Result<TcpListener> {
/// #     todo!("see SkReuseport docs for the full listener setup")
/// # }
/// # let first = reuseport_listener(0)?;
/// # let port = first.local_addr()?.port();
/// # let sockets = [first, reuseport_listener(port)?];
///
/// let mut socket_array: ReusePortSockArray<_> = bpf.take_map("socket_map").unwrap().try_into()?;
/// for (index, socket) in sockets.iter().enumerate() {
///     socket_array.set(index as u32, socket, 0)?;
/// }
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

    /// An iterator over the indices of the array that point to a socket.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
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
