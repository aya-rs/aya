use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    Pod,
    maps::{IterableMap, MapData, MapError, MapIter, MapKeys, check_kv_size, hash_map},
    sys::{SyscallError, bpf_map_lookup_elem},
};

/// A hash map that can be shared between eBPF programs and user space.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::HashMap;
///
/// let mut redirect_ports = HashMap::try_from(bpf.map_mut("REDIRECT_PORTS").unwrap())?;
///
/// // redirect port 80 to 8080
/// redirect_ports.insert(80, 8080, 0);
/// // redirect port 443 to 8443
/// redirect_ports.insert(443, 8443, 0);
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_HASH")]
#[doc(alias = "BPF_MAP_TYPE_LRU_HASH")]
#[derive(Debug)]
pub struct HashMap<T, K, V> {
    pub(crate) inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> HashMap<T, K, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<K, V>(data)?;

        Ok(Self {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a copy of the value associated with the key.
    pub fn get(&self, key: &K, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|io_error| SyscallError {
            call: "bpf_map_lookup_elem",
            io_error,
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub fn iter(&self) -> MapIter<'_, K, V, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element
    /// type is `Result<K, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, K> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: BorrowMut<MapData>, K: Pod, V: Pod> HashMap<T, K, V> {
    /// Inserts a key-value pair into the map.
    pub fn insert(
        &mut self,
        key: impl Borrow<K>,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(self.inner.borrow_mut(), key.borrow(), value.borrow(), flags)
    }

    /// Removes a key from the map.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), key)
    }
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> IterableMap<K, V> for HashMap<T, K, V> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &K) -> Result<V, MapError> {
        Self::get(self, key, 0)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use assert_matches::assert_matches;
    use aya_obj::generated::{
        bpf_attr, bpf_cmd,
        bpf_map_type::{BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LRU_HASH},
    };
    use libc::{EFAULT, ENOENT};

    use super::*;
    use crate::{
        maps::{
            Map,
            test_utils::{self, new_map},
        },
        sys::{SysResult, Syscall, override_syscall},
    };

    fn new_obj_map() -> aya_obj::Map {
        test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_HASH)
    }

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_key_size() {
        let map = new_map(new_obj_map());
        assert_matches!(
            HashMap::<_, u8, u32>::new(&map),
            Err(MapError::InvalidKeySize {
                size: 1,
                expected: 4
            })
        );
    }

    #[test]
    fn test_wrong_value_size() {
        let map = new_map(new_obj_map());
        assert_matches!(
            HashMap::<_, u32, u16>::new(&map),
            Err(MapError::InvalidValueSize {
                size: 2,
                expected: 4
            })
        );
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = new_map(new_obj_map());
        let map = Map::Array(map);
        assert_matches!(
            HashMap::<_, u8, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_try_from_wrong_map_values() {
        let map = new_map(new_obj_map());
        let map = Map::HashMap(map);
        assert_matches!(
            HashMap::<_, u32, u16>::try_from(&map),
            Err(MapError::InvalidValueSize {
                size: 2,
                expected: 4
            })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        let _: HashMap<_, u32, u32> = HashMap::new(&map).unwrap();
    }

    #[test]
    fn test_try_from_ok() {
        let map = new_map(new_obj_map());
        let map = Map::HashMap(map);
        let _: HashMap<_, u32, u32> = map.try_into().unwrap();
    }

    #[test]
    fn test_try_from_ok_lru() {
        let map_data = || new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_LRU_HASH));
        let map = Map::HashMap(map_data());
        let _: HashMap<_, u32, u32> = map.try_into().unwrap();
        let map = Map::LruHashMap(map_data());
        let _: HashMap<_, u32, u32> = map.try_into().unwrap();
    }

    #[test]
    fn test_insert_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.insert(1, 42, 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_update_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_insert_ok() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert_matches!(hm.insert(1, 42, 0), Ok(()));
    }

    #[test]
    fn test_insert_boxed_ok() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert_matches!(hm.insert(Box::new(1), Box::new(42), 0), Ok(()));
    }

    #[test]
    fn test_remove_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            hm.remove(&1),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_delete_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_remove_ok() {
        let mut map = new_map(new_obj_map());
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_DELETE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert_matches!(hm.remove(&1), Ok(()));
    }

    #[test]
    fn test_get_syscall_error() {
        let map = new_map(new_obj_map());
        override_syscall(|_| sys_error(EFAULT));
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        assert_matches!(
            hm.get(&1, 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_lookup_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_get_not_found() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        assert_matches!(hm.get(&1, 0), Err(MapError::KeyNotFound));
    }

    fn bpf_key<T: Copy>(attr: &bpf_attr) -> Option<T> {
        match unsafe { attr.__bindgen_anon_2.key } as *const T {
            p if p.is_null() => None,
            p => Some(unsafe { *p }),
        }
    }

    fn set_next_key<T: Copy>(attr: &bpf_attr, next: T) -> SysResult {
        let key =
            (unsafe { attr.__bindgen_anon_2.__bindgen_anon_1.next_key } as *const T).cast_mut();
        unsafe { *key = next };
        Ok(0)
    }

    fn set_ret<T: Copy>(attr: &bpf_attr, ret: T) -> SysResult {
        let value =
            (unsafe { attr.__bindgen_anon_2.__bindgen_anon_1.value } as *const T).cast_mut();
        unsafe { *value = ret };
        Ok(0)
    }

    #[test]
    fn test_keys_empty() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();
        let keys = hm.keys().collect::<Result<Vec<_>, _>>();
        assert_matches!(keys, Ok(ks) if ks.is_empty())
    }

    fn get_next_key(attr: &bpf_attr) -> SysResult {
        match bpf_key(attr) {
            None => set_next_key(attr, 10),
            Some(10) => set_next_key(attr, 20),
            Some(20) => set_next_key(attr, 30),
            Some(30) => sys_error(ENOENT),
            Some(_) => sys_error(EFAULT),
        }
    }

    fn lookup_elem(attr: &bpf_attr) -> SysResult {
        match bpf_key(attr) {
            Some(10) => set_ret(attr, 100),
            Some(20) => set_ret(attr, 200),
            Some(30) => set_ret(attr, 300),
            Some(_) => sys_error(ENOENT),
            None => sys_error(EFAULT),
        }
    }

    #[test]
    fn test_keys() {
        let map = new_map(new_obj_map());

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(attr),
            _ => sys_error(EFAULT),
        });

        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let keys = hm.keys().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(&keys, &[10, 20, 30])
    }

    #[test]
    fn test_keys_error() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => match bpf_key(attr) {
                None => set_next_key(attr, 10),
                Some(10) => set_next_key(attr, 20),
                Some(_) => sys_error(EFAULT),
            },
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let mut keys = hm.keys();
        assert_matches!(keys.next(), Some(Ok(10)));
        assert_matches!(keys.next(), Some(Ok(20)));
        assert_matches!(
            keys.next(),
            Some(Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_get_next_key",
                io_error: _
            })))
        );
        assert_matches!(keys.next(), None);
    }

    #[test]
    fn test_iter() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(attr),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => lookup_elem(attr),
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();
        let items = hm.iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(&items, &[(10, 100), (20, 200), (30, 300)])
    }

    #[test]
    fn test_iter_key_deleted() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(attr),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => match bpf_key(attr) {
                Some(10) => set_ret(attr, 100),
                Some(20) => sys_error(ENOENT),
                Some(30) => set_ret(attr, 300),
                Some(_) => sys_error(ENOENT),
                None => sys_error(EFAULT),
            },
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let items = hm.iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(&items, &[(10, 100), (30, 300)])
    }

    #[test]
    fn test_iter_key_error() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => match bpf_key(attr) {
                None => set_next_key(attr, 10),
                Some(10) => set_next_key(attr, 20),
                Some(20) => sys_error(EFAULT),
                Some(30) => sys_error(ENOENT),
                Some(i) => panic!("invalid key {i}"),
            },
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => lookup_elem(attr),
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let mut iter = hm.iter();
        assert_matches!(iter.next(), Some(Ok((10, 100))));
        assert_matches!(iter.next(), Some(Ok((20, 200))));
        assert_matches!(
            iter.next(),
            Some(Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_get_next_key",
                io_error: _
            })))
        );
        assert_matches!(iter.next(), None);
    }

    #[test]
    fn test_iter_value_error() {
        let map = new_map(new_obj_map());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(attr),
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => match bpf_key(attr) {
                Some(10) => set_ret(attr, 100),
                Some(20) => sys_error(EFAULT),
                Some(30) => set_ret(attr, 300),
                Some(_) => sys_error(ENOENT),
                None => sys_error(EFAULT),
            },
            _ => sys_error(EFAULT),
        });
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let mut iter = hm.iter();
        assert_matches!(iter.next(), Some(Ok((10, 100))));
        assert_matches!(
            iter.next(),
            Some(Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_lookup_elem",
                io_error: _
            })))
        );
        assert_matches!(iter.next(), Some(Ok((30, 300))));
        assert_matches!(iter.next(), None);
    }
}
