//! An array of AF_XDP sockets.

use std::{
    convert::TryFrom,
    mem,
    ops::{Deref, DerefMut},
    os::unix::prelude::{AsRawFd, RawFd},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_XSKMAP,
    maps::{Map, MapError, MapRef, MapRefMut},
    sys::bpf_map_update_elem,
};

/// An array of AF_XDP sockets.
///
/// XDP programs can use this map to redirect packets to a target
/// AF_XDP socket using the `XDP_REDIRECT` action.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.2.
///
/// # Examples
/// ```no_run
/// # let bpf = aya::Bpf::load(&[])?;
/// # let socket_fd = 1;
/// use aya::maps::XskMap;
/// use std::convert::{TryFrom, TryInto};
///
/// let mut xskmap = XskMap::try_from(bpf.map_mut("SOCKETS")?)?;
/// // socket_fd is the RawFd of an AF_XDP socket
/// xskmap.set(0, socket_fd, 0);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_XSKMAP")]
pub struct XskMap<T: Deref<Target = Map>> {
    inner: T,
}

impl<T: Deref<Target = Map>> XskMap<T> {
    fn new(map: T) -> Result<XskMap<T>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_XSKMAP as u32 {
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

        Ok(XskMap { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.obj.def.max_entries
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

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> XskMap<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set<V: AsRawFd>(&mut self, index: u32, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, &index, &value.as_raw_fd(), flags).map_err(
            |(code, io_error)| MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            },
        )?;
        Ok(())
    }
}

impl TryFrom<MapRef> for XskMap<MapRef> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<XskMap<MapRef>, MapError> {
        XskMap::new(a)
    }
}

impl TryFrom<MapRefMut> for XskMap<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<XskMap<MapRefMut>, MapError> {
        XskMap::new(a)
    }
}
