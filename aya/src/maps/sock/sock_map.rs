//! An array of eBPF program file descriptors used as a jump table.

use std::{
    convert::TryFrom,
    mem,
    ops::{Deref, DerefMut},
    os::unix::{io::AsRawFd, prelude::RawFd},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_SOCKMAP,
    maps::{sock::SocketMap, Map, MapError, MapKeys, MapRef, MapRefMut},
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
/// # let mut bpf = aya::Bpf::load(&[], None)?;
/// use std::convert::{TryFrom, TryInto};
/// use aya::maps::SockMap;
/// use aya::programs::SkSkb;
///
/// let intercept_ingress = SockMap::try_from(bpf.map_mut("INTERCEPT_INGRESS")?)?;
/// let prog: &mut SkSkb = bpf.program_mut("intercept_ingress_packet")?.try_into()?;
/// prog.load()?;
/// prog.attach(&intercept_ingress)?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_SOCKMAP")]
pub struct SockMap<T: Deref<Target = Map>> {
    pub(crate) inner: T,
}

impl<T: Deref<Target = Map>> SockMap<T> {
    fn new(map: T) -> Result<SockMap<T>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_SOCKMAP as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let expected = mem::size_of::<u32>();
        let size = map.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let expected = mem::size_of::<RawFd>();
        let size = map.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = map.fd_or_err()?;

        Ok(SockMap { inner: map })
    }

    /// An iterator over the indices of the array that point to a program. The iterator item type
    /// is `Result<u32, MapError>`.
    pub unsafe fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(&self.inner)
    }

    fn check_bounds(&self, index: u32) -> Result<(), MapError> {
        let max_entries = self.inner.obj.def.max_entries;
        if index >= self.inner.obj.def.max_entries {
            Err(MapError::OutOfBounds { index, max_entries })
        } else {
            Ok(())
        }
    }
}

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> SockMap<T> {
    /// Stores a socket into the map.
    pub fn set<I: AsRawFd>(&mut self, index: u32, socket: &I, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, &index, &socket.as_raw_fd(), flags).map_err(
            |(code, io_error)| MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            },
        )?;
        Ok(())
    }

    /// Removes the socket stored at `index` from the map.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        self.check_bounds(*index)?;
        bpf_map_delete_elem(fd, index)
            .map(|_| ())
            .map_err(|(code, io_error)| MapError::SyscallError {
                call: "bpf_map_delete_elem".to_owned(),
                code,
                io_error,
            })
    }
}

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> SocketMap for SockMap<T> {
    fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.inner.fd_or_err()
    }
}

impl TryFrom<MapRef> for SockMap<MapRef> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<SockMap<MapRef>, MapError> {
        SockMap::new(a)
    }
}

impl TryFrom<MapRefMut> for SockMap<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<SockMap<MapRefMut>, MapError> {
        SockMap::new(a)
    }
}
