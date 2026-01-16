use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    Pod,
    maps::{MapData, MapError, MapFd, check_kv_size, hash_map, info::MapInfo},
    sys::{SyscallError, bpf_map_get_fd_by_id, bpf_map_lookup_elem},
};

/// An hashmap of eBPF Maps
///
/// A `HashMap` is used to store references to other maps.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
#[doc(alias = "BPF_MAP_TYPE_HASH")]
#[doc(alias = "BPF_MAP_TYPE_LRU_HASH")]
#[derive(Debug)]
pub struct HashMap<T, K> {
    pub(crate) inner: T,
    _k: PhantomData<K>,
}

impl<T: Borrow<MapData>, K: Pod> HashMap<T, K> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<K, u32>(data)?;

        Ok(Self {
            inner: map,
            _k: PhantomData,
        })
    }

    /// Returns the inner map associated with the key.
    ///
    /// The returned map can be used to read and write values. If you only need
    /// the file descriptor, you can call `.fd()` on the returned map.
    pub fn get<IK: Pod, IV: Pod>(
        &self,
        key: &K,
        flags: u64,
    ) -> Result<crate::maps::HashMap<MapData, IK, IV>, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let value: Option<u32> =
            bpf_map_lookup_elem(fd, key, flags).map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        if let Some(id) = value {
            let inner_fd = bpf_map_get_fd_by_id(id)?;
            let info = MapInfo::new_from_fd(inner_fd.as_fd())?;
            let map_data = MapData::from_id(info.id())?;
            crate::maps::HashMap::new(map_data)
        } else {
            Err(MapError::KeyNotFound)
        }
    }
}

impl<T: BorrowMut<MapData>, K: Pod> HashMap<T, K> {
    /// Inserts a key-value pair into the map.
    pub fn insert(
        &mut self,
        key: impl Borrow<K>,
        value: &MapFd,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            key.borrow(),
            &value.as_fd().as_raw_fd(),
            flags,
        )
    }

    /// Removes a key from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), key)
    }
}
