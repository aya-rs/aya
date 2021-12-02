//! An array of eBPF maps.

use std::{
    convert::TryFrom,
    mem,
    ops::{Deref, DerefMut},
    os::unix::{io::IntoRawFd, prelude::RawFd},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS,
    maps::{of_maps::MapOfMaps, Map, MapError, MapKeys, MapRef, MapRefMut},
    sys::{bpf_map_delete_elem, bpf_map_get_fd_by_id, bpf_map_lookup_elem, bpf_map_update_elem},
};

/// An array of eBPF Maps
///
/// A `Array` is used to store references to other maps.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
#[doc(alias = "BPF_MAP_TYPE_ARRAY_OF_MAPS")]
pub struct Array<T: Deref<Target = Map>> {
    pub(crate) inner: T,
}

impl<T: Deref<Target = Map>> Array<T> {
    fn new(map: T) -> Result<Array<T>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_ARRAY_OF_MAPS as u32 {
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

        Ok(Array { inner: map })
    }

    /// An iterator over the indices of the array that point to a map. The iterator item type
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

    /// Returns the fd of the map stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: &u32, flags: u64) -> Result<RawFd, MapError> {
        self.check_bounds(*index)?;
        let fd = self.inner.fd_or_err()?;

        let id = bpf_map_lookup_elem(fd, index, flags)
            .map_err(|(code, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                code,
                io_error,
            })?
            .ok_or(MapError::KeyNotFound)?;
        let inner_fd = bpf_map_get_fd_by_id(id).map_err(|io_error| MapError::SyscallError {
            call: "bpf_map_get_fd_by_id".to_owned(),
            code: 0,
            io_error,
        })?;
        Ok(inner_fd as RawFd)
    }
}

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> Array<T> {
    /// Stores a map fd into the map.
    pub fn set<I: IntoRawFd>(&mut self, index: u32, map: I, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        let map_fd = map.into_raw_fd();
        self.check_bounds(index)?;
        bpf_map_update_elem(fd, &index, &map_fd, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        // safety: we're closing a RawFd which we have ownership of
        // this is required because inserting this in to the map causes
        // there to be a reference to the map in both kernel and userspace
        unsafe { libc::close(map_fd) };
        Ok(())
    }

    /// Removes the map stored at `index` from the map.
    pub fn delete(&mut self, index: &u32) -> Result<(), MapError> {
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

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> MapOfMaps for Array<T> {
    fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.inner.fd_or_err()
    }
}

impl TryFrom<MapRef> for Array<MapRef> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<Array<MapRef>, MapError> {
        Array::new(a)
    }
}

impl TryFrom<MapRefMut> for Array<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<Array<MapRefMut>, MapError> {
        Array::new(a)
    }
}
