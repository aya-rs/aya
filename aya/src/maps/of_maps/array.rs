//! An array of eBPF maps.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    Pod,
    maps::{MapData, MapError, MapFd, check_bounds, check_kv_size, info::MapInfo},
    sys::{SyscallError, bpf_map_get_fd_by_id, bpf_map_lookup_elem, bpf_map_update_elem},
};

/// An array of eBPF Maps
///
/// A `Array` is used to store references to other maps.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
#[doc(alias = "BPF_MAP_TYPE_ARRAY_OF_MAPS")]
pub struct Array<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> Array<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, u32>(data)?;
        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().obj.max_entries()
    }

    /// Returns true if the array is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the inner map stored at the given index.
    ///
    /// The returned map can be used to read and write values. If you only need
    /// the file descriptor, you can call `.fd()` on the returned map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get<V: Pod>(&self, index: &u32, flags: u64) -> Result<crate::maps::Array<MapData, V>, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, *index)?;
        let fd = data.fd().as_fd();

        let value: Option<u32> =
            bpf_map_lookup_elem(fd, index, flags).map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        if let Some(id) = value {
            let inner_fd = bpf_map_get_fd_by_id(id)?;
            let info = MapInfo::new_from_fd(inner_fd.as_fd())?;
            let map_data = MapData::from_id(info.id())?;
            crate::maps::Array::new(map_data)
        } else {
            Err(MapError::KeyNotFound)
        }
    }
}
impl<T: BorrowMut<MapData>> Array<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: &MapFd, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        let fd = data.fd().as_fd();
        bpf_map_update_elem(fd, Some(&index), &value.as_fd().as_raw_fd(), flags).map_err(
            |io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            },
        )?;
        Ok(())
    }
}
