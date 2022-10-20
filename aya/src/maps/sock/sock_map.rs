//! An array of eBPF program file descriptors used as a jump table.

use std::{
    convert::{AsMut, AsRef},
    os::unix::{io::AsRawFd, prelude::RawFd},
};

use crate::{
    maps::{check_bounds, check_kv_size, sock::SockMapFd, MapData, MapError, MapKeys},
    sys::{bpf_map_delete_elem, bpf_map_update_elem},
};

/// An array of TCP or UDP sockets.
///
/// A `SockMap` is used to store TCP or UDP sockets. eBPF programs can then be
/// attached to the map to inspect, filter or redirect network buffers on those
/// sockets.
///
/// A `SockMap` can also be used to redirect packets to sockets contained by the
/// map using `bpf_redirect_map()`, `bpf_sk_redirect_map()` etc.    
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress = SockMap::try_from(bpf.map("INTERCEPT_INGRESS").unwrap())?;
/// let map_fd = intercept_ingress.fd()?;
///
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach(map_fd)?;
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKMAP")]
pub struct SockMap<T> {
    pub(crate) inner: T,
}

impl<T: AsRef<MapData>> SockMap<T> {
    pub(crate) fn new(map: T) -> Result<SockMap<T>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, RawFd>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(SockMap { inner: map })
    }

    /// An iterator over the indices of the array that point to a program. The iterator item type
    /// is `Result<u32, MapError>`.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.as_ref())
    }

    /// Returns the map's file descriptor.
    ///
    /// The returned file descriptor can be used to attach programs that work with
    /// socket maps, like [`SkMsg`](crate::programs::SkMsg) and [`SkSkb`](crate::programs::SkSkb).
    pub fn fd(&self) -> Result<SockMapFd, MapError> {
        Ok(SockMapFd(self.inner.as_ref().fd_or_err()?))
    }
}

impl<T: AsMut<MapData>> SockMap<T> {
    /// Stores a socket into the map.
    pub fn set<I: AsRawFd>(&mut self, index: u32, socket: &I, flags: u64) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        let fd = data.fd_or_err()?;
        check_bounds(data, index)?;
        bpf_map_update_elem(fd, Some(&index), &socket.as_raw_fd(), flags).map_err(
            |(_, io_error)| MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            },
        )?;
        Ok(())
    }

    /// Removes the socket stored at `index` from the map.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        let fd = data.fd_or_err()?;
        check_bounds(data, *index)?;
        bpf_map_delete_elem(fd, index)
            .map(|_| ())
            .map_err(|(_, io_error)| MapError::SyscallError {
                call: "bpf_map_delete_elem".to_owned(),
                io_error,
            })
    }
}
