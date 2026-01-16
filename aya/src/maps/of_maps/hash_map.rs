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

#[cfg(test)]
mod tests {
    use std::io;

    use assert_matches::assert_matches;
    use aya_obj::generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS};
    use libc::{EFAULT, ENOENT};

    use super::*;
    use crate::{
        maps::{Map, test_utils},
        sys::{SysResult, Syscall, override_syscall},
    };

    fn new_obj_map() -> aya_obj::Map {
        test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_HASH_OF_MAPS)
    }

    fn new_map(obj: aya_obj::Map) -> MapData {
        test_utils::new_map(obj)
    }

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_key_size() {
        let map = new_map(new_obj_map());
        assert_matches!(
            HashMap::<_, u8>::new(&map),
            Err(MapError::InvalidKeySize {
                size: 1,
                expected: 4
            })
        );
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_HASH,
        ));
        let map = Map::HashMap(map);
        assert_matches!(
            HashMap::<_, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        assert!(HashMap::<_, u32>::new(&map).is_ok());
    }

    #[test]
    fn test_insert_syscall_error() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_HASH,
        ));
        let mut hm = HashMap::<_, u32>::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.insert(1, inner_map.fd(), 0),
            Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_update_elem",
                ..
            }))
        );
    }

    #[test]
    fn test_insert_ok() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_HASH,
        ));
        let mut hm = HashMap::<_, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert!(hm.insert(1, inner_map.fd(), 0).is_ok());
    }

    #[test]
    fn test_remove_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32>::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.remove(&1),
            Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_delete_elem",
                ..
            }))
        );
    }

    #[test]
    fn test_remove_ok() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_DELETE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert!(hm.remove(&1).is_ok());
    }

    #[test]
    fn test_get_syscall_error() {
        let map = new_map(new_obj_map());
        let hm = HashMap::<_, u32>::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.get::<u32, u32>(&1, 0),
            Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_lookup_elem",
                ..
            }))
        );
    }

    #[test]
    fn test_get_not_found() {
        let map = new_map(new_obj_map());
        let hm = HashMap::<_, u32>::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        assert_matches!(hm.get::<u32, u32>(&1, 0), Err(MapError::KeyNotFound));
    }

    #[test]
    fn test_keys_empty() {
        let map = new_map(new_obj_map());
        let hm = HashMap::<_, u32>::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        let keys: Result<Vec<_>, _> = hm.keys().collect();
        assert_matches!(keys, Ok(ks) if ks.is_empty());
    }
}
