use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    maps::{check_kv_size, hash_map, MapData, MapError, MapFd},
    sys::{bpf_map_get_fd_by_id, bpf_map_lookup_elem, SyscallError},
    Pod,
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

    /// Returns a copy of the value associated with the key.
    pub fn get(&self, key: &K, flags: u64) -> Result<MapFd, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|(_, io_error)| SyscallError {
            call: "bpf_map_lookup_elem",
            io_error,
        })?;
        if let Some(value) = value {
            let fd = bpf_map_get_fd_by_id(value)?;
            Ok(MapFd::from_fd(fd))
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
