//! An array of BPF maps (BPF_MAP_TYPE_ARRAY_OF_MAPS).

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd as _, AsRawFd as _, RawFd},
};

use crate::maps::{check_bounds, check_kv_size, hash_map, MapData, MapError, MapFd, MapKeys};

/// An array of BPF maps (`BPF_MAP_TYPE_ARRAY_OF_MAPS`).
///
/// Each entry in the outer array holds a file descriptor to an inner BPF map.
/// The inner maps must all share the same type, key_size, and value_size
/// (established at outer map creation time via a template).
///
/// From userspace, you can insert and remove inner maps at specific indices.
/// From eBPF programs, `bpf_map_lookup_elem` on the outer map returns a pointer
/// to the inner map that can then be used with another `bpf_map_lookup_elem`.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::ArrayOfMaps;
/// use aya::maps::Array;
///
/// let mut outer = ArrayOfMaps::try_from(bpf.take_map("OUTER_MAP").unwrap())?;
///
/// // Create or obtain an inner map fd, then insert it at index 0
/// // outer.set(0, inner_map_fd, 0)?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_ARRAY_OF_MAPS")]
pub struct ArrayOfMaps<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> ArrayOfMaps<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, RawFd>(data)?;

        Ok(Self { inner: map })
    }

    /// An iterator over the indices of the array that have an inner map set.
    pub fn indices(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }

    /// Returns the map's file descriptor.
    pub fn fd(&self) -> &MapFd {
        self.inner.borrow().fd()
    }
}

impl<T: BorrowMut<MapData>> ArrayOfMaps<T> {
    /// Sets the inner map at `index` to the map identified by `map_fd`.
    ///
    /// The inner map must have the same type, key_size, and value_size as the
    /// template used when the outer map was created. The inner map's max_entries
    /// may differ from the template.
    pub fn set(&mut self, index: u32, map_fd: &MapFd, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        hash_map::insert(data, &index, &map_fd.as_fd().as_raw_fd(), flags)
    }

    /// Removes the inner map at `index`.
    pub fn clear_index(&mut self, index: &u32) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, *index)?;
        hash_map::remove(data, index)
    }
}
