//! A hash map of eBPF maps.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    Pod,
    maps::{FromMapData, InnerMap, MapData, MapError, MapKeys, check_kv_size, hash_map},
    sys::{SyscallError, bpf_map_lookup_elem},
};

/// A hashmap of eBPF maps.
///
/// A `HashOfMaps` stores references to other eBPF maps, keyed by an arbitrary key type.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
#[doc(alias = "BPF_MAP_TYPE_HASH_OF_MAPS")]
#[derive(Debug)]
pub struct HashOfMaps<T, K> {
    pub(crate) inner: T,
    _k: PhantomData<K>,
}

impl<T: Borrow<MapData>, K: Pod> HashOfMaps<T, K> {
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
    /// The type parameter `M` specifies the expected inner map type. It must
    /// implement [`FromMapData`], which validates and wraps the raw [`MapData`].
    /// Use `MapData` as `M` to retrieve an untyped handle.
    ///
    /// # File descriptor cost
    ///
    /// Each call opens a **new file descriptor** to the inner map. The caller
    /// owns the returned map and its FD is closed on drop. Avoid calling this
    /// in a tight loop without dropping previous results.
    pub fn get<M: FromMapData>(&self, key: &K, flags: u64) -> Result<M, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let value: Option<u32> =
            bpf_map_lookup_elem(fd, key, flags).map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        match value {
            Some(id) => super::map_from_id(id),
            None => Err(MapError::KeyNotFound),
        }
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: BorrowMut<MapData>, K: Pod> HashOfMaps<T, K> {
    /// Inserts a key-value pair into the map.
    pub fn insert(
        &mut self,
        key: impl Borrow<K>,
        value: &impl InnerMap,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            key.borrow(),
            &value.fd().as_fd().as_raw_fd(),
            flags,
        )
    }

    /// Removes a key from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), key)
    }
}

impl<K: Pod> HashOfMaps<MapData, K> {
    /// Returns a reference to the underlying [`MapData`].
    pub const fn map_data(&self) -> &MapData {
        &self.inner
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
            HashOfMaps::<_, u8>::new(&map),
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
            HashOfMaps::<_, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        HashOfMaps::<_, u32>::new(&map).unwrap();
    }

    #[test]
    fn test_insert_syscall_error() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_HASH,
        ));
        let mut hm = HashOfMaps::<_, u32>::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.insert(1, &inner_map, 0),
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
        let mut hm = HashOfMaps::<_, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        hm.insert(1, &inner_map, 0).unwrap();
    }

    #[test]
    fn test_remove_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashOfMaps::<_, u32>::new(&mut map).unwrap();

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
        let mut hm = HashOfMaps::<_, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_DELETE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        hm.remove(&1).unwrap();
    }

    #[test]
    fn test_get_syscall_error() {
        let map = new_map(new_obj_map());
        let hm = HashOfMaps::<_, u32>::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.get::<crate::maps::HashMap<MapData, u32, u32>>(&1, 0),
            Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_lookup_elem",
                ..
            }))
        );
    }

    #[test]
    fn test_get_not_found() {
        let map = new_map(new_obj_map());
        let hm = HashOfMaps::<_, u32>::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        assert_matches!(
            hm.get::<crate::maps::HashMap<MapData, u32, u32>>(&1, 0),
            Err(MapError::KeyNotFound)
        );
    }

    #[test]
    fn test_keys_empty() {
        let map = new_map(new_obj_map());
        let hm = HashOfMaps::<_, u32>::new(&map).unwrap();

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
