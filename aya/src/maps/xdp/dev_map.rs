//! An array of network devices.

use std::{
    convert::TryFrom,
    mem,
    ops::{Deref, DerefMut},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_DEVMAP,
    maps::{Map, MapError, MapRef, MapRefMut},
    sys::bpf_map_update_elem,
};

/// An array of network devices.
///
/// XDP programs can use this map to redirect to other network
/// devices.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.2.
///
/// # Examples
/// ```no_run
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::xdp::DevMap;
/// use std::convert::{TryFrom, TryInto};
///
/// let mut devmap = DevMap::try_from(bpf.map_mut("IFACES")?)?;
/// let ifindex = 32u32;
/// devmap.set(ifindex, ifindex, 0);
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_DEVMAP")]
pub struct DevMap<T: Deref<Target = Map>> {
    inner: T,
}

impl<T: Deref<Target = Map>> DevMap<T> {
    fn new(map: T) -> Result<DevMap<T>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_DEVMAP as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let expected = mem::size_of::<u32>();
        let size = map.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let expected = mem::size_of::<u32>();
        let size = map.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = map.fd_or_err()?;

        Ok(DevMap { inner: map })
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

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> DevMap<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: u32, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, &index, &value, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        Ok(())
    }
}

impl TryFrom<MapRef> for DevMap<MapRef> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<DevMap<MapRef>, MapError> {
        DevMap::new(a)
    }
}

impl TryFrom<MapRefMut> for DevMap<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<DevMap<MapRefMut>, MapError> {
        DevMap::new(a)
    }
}
