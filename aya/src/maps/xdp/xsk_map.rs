//! An array of AF_XDP sockets.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd, AsRawFd, RawFd},
};

use crate::{
    maps::{check_bounds, check_kv_size, MapData, MapError},
    sys::{bpf_map_update_elem, SyscallError},
};

/// An array of AF_XDP sockets.
///
/// XDP programs can use this map to redirect packets to a target
/// AF_XDP socket using the `XDP_REDIRECT` action.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// # let socket_fd = 1;
/// use aya::maps::XskMap;
///
/// let mut xskmap = XskMap::try_from(bpf.map_mut("SOCKETS").unwrap())?;
/// // socket_fd is the RawFd of an AF_XDP socket
/// xskmap.set(0, socket_fd, 0);
/// # Ok::<(), aya::EbpfError>(())
/// ```
///
/// # See also
///
/// Kernel documentation: <https://docs.kernel.org/next/bpf/map_xskmap.html>
#[doc(alias = "BPF_MAP_TYPE_XSKMAP")]
pub struct XskMap<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> XskMap<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, RawFd>(data)?;

        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().def.max_entries()
    }
}

impl<T: BorrowMut<MapData>> XskMap<T> {
    /// Sets the `AF_XDP` socket at a given index.
    ///
    /// When redirecting a packet, the `AF_XDP` socket at `index` will recieve the packet. Note
    /// that it will do so only if the socket is bound to the same queue the packet was recieved
    /// on.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, socket_fd: impl AsRawFd, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        let fd = data.fd().as_fd();
        bpf_map_update_elem(fd, Some(&index), &socket_fd.as_raw_fd(), flags).map_err(
            |(_, io_error)| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            },
        )?;
        Ok(())
    }
}
