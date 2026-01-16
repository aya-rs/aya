use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    Pod,
    maps::{MapData, MapError, MapFd, MapKeys, check_kv_size, hash_map, info::MapInfo},
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

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(self.inner.borrow())
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The iterator item
    /// type is `Result<(K, HashMap<MapData, IK, IV>), MapError>`.
    pub fn iter<IK: Pod, IV: Pod>(&self) -> HashMapOfMapsIter<'_, T, K, IK, IV> {
        HashMapOfMapsIter::new(self)
    }
}

/// Iterator over a HashMapOfMaps.
pub struct HashMapOfMapsIter<'coll, T, K: Pod, IK: Pod, IV: Pod> {
    keys: MapKeys<'coll, K>,
    map: &'coll HashMap<T, K>,
    _ik: PhantomData<IK>,
    _iv: PhantomData<IV>,
}

impl<'coll, T: Borrow<MapData>, K: Pod, IK: Pod, IV: Pod> HashMapOfMapsIter<'coll, T, K, IK, IV> {
    fn new(map: &'coll HashMap<T, K>) -> Self {
        Self {
            keys: MapKeys::new(map.inner.borrow()),
            map,
            _ik: PhantomData,
            _iv: PhantomData,
        }
    }
}

impl<T: Borrow<MapData>, K: Pod, IK: Pod, IV: Pod> Iterator
    for HashMapOfMapsIter<'_, T, K, IK, IV>
{
    type Item = Result<(K, crate::maps::HashMap<MapData, IK, IV>), MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.keys.next() {
                Some(Ok(key)) => match self.map.get::<IK, IV>(&key, 0) {
                    Ok(inner_map) => return Some(Ok((key, inner_map))),
                    Err(MapError::KeyNotFound) => continue,
                    Err(e) => return Some(Err(e)),
                },
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
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

impl<K: Pod> HashMap<MapData, K> {
    /// Returns a reference to the underlying [`MapData`].
    pub fn map_data(&self) -> &MapData {
        &self.inner
    }

    /// Returns a file descriptor reference to the underlying map.
    pub fn fd(&self) -> &MapFd {
        self.inner.fd()
    }
}
