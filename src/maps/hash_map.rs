use std::{convert::TryFrom, marker::PhantomData, mem, os::unix::prelude::RawFd};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_HASH,
    syscalls::{
        bpf_map_delete_elem, bpf_map_get_next_key, bpf_map_lookup_and_delete_elem,
        bpf_map_lookup_elem, bpf_map_update_elem,
    },
};

use super::{Map, MapError};
use crate::Pod;

pub struct HashMap<T: AsRef<Map>, K, V> {
    inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<T: AsRef<Map>, K: Pod, V: Pod> HashMap<T, K, V> {
    pub fn new(map: T) -> Result<HashMap<T, K, V>, MapError> {
        let inner = map.as_ref();
        let map_type = inner.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_HASH {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            })?;
        }
        let size = mem::size_of::<K>();
        let expected = inner.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let size = mem::size_of::<V>();
        let expected = inner.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }

        Ok(HashMap {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub unsafe fn get(&self, key: &K, flags: u64) -> Result<Option<V>, MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        bpf_map_lookup_elem(fd, key, flags)
            .map_err(|(code, io_error)| MapError::LookupElementFailed { code, io_error })
    }

    pub unsafe fn iter<'coll>(&'coll self) -> MapIter<'coll, K, V> {
        MapIter::new(self)
    }

    pub unsafe fn keys<'coll>(&'coll self) -> MapKeys<'coll, K, V> {
        MapKeys::new(self)
    }
}

impl<T: AsRef<Map> + AsMut<Map>, K: Pod, V: Pod> HashMap<T, K, V> {
    pub fn insert(&mut self, key: K, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        bpf_map_update_elem(fd, &key, &value, flags)
            .map_err(|(code, io_error)| MapError::UpdateElementFailed { code, io_error })?;
        Ok(())
    }

    pub unsafe fn pop(&mut self, key: &K) -> Result<Option<V>, MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        bpf_map_lookup_and_delete_elem(fd, key)
            .map_err(|(code, io_error)| MapError::LookupAndDeleteElementFailed { code, io_error })
    }

    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        bpf_map_delete_elem(fd, key)
            .map(|_| ())
            .map_err(|(code, io_error)| MapError::DeleteElementFailed { code, io_error })
    }
}

impl<'a, K: Pod, V: Pod> TryFrom<&'a Map> for HashMap<&'a Map, K, V> {
    type Error = MapError;

    fn try_from(inner: &'a Map) -> Result<HashMap<&'a Map, K, V>, MapError> {
        HashMap::new(inner)
    }
}

impl<'a, K: Pod, V: Pod> TryFrom<&'a mut Map> for HashMap<&'a mut Map, K, V> {
    type Error = MapError;

    fn try_from(inner: &'a mut Map) -> Result<HashMap<&'a mut Map, K, V>, MapError> {
        HashMap::new(inner)
    }
}

pub(crate) trait IterableMap<K: Pod, V: Pod> {
    fn fd(&self) -> Result<RawFd, MapError>;
    unsafe fn get(&self, key: &K) -> Result<Option<V>, MapError>;
}

impl<T: AsRef<Map>, K: Pod, V: Pod> IterableMap<K, V> for HashMap<T, K, V> {
    fn fd(&self) -> Result<RawFd, MapError> {
        self.inner.as_ref().fd_or_err()
    }

    unsafe fn get(&self, key: &K) -> Result<Option<V>, MapError> {
        HashMap::get(self, key, 0)
    }
}

pub struct MapKeys<'coll, K: Pod, V: Pod> {
    map: &'coll dyn IterableMap<K, V>,
    err: bool,
    key: Option<K>,
}

impl<'coll, K: Pod, V: Pod> MapKeys<'coll, K, V> {
    fn new(map: &'coll dyn IterableMap<K, V>) -> MapKeys<'coll, K, V> {
        MapKeys {
            map,
            err: false,
            key: None,
        }
    }
}

impl<K: Pod, V: Pod> Iterator for MapKeys<'_, K, V> {
    type Item = Result<K, MapError>;

    fn next(&mut self) -> Option<Result<K, MapError>> {
        if self.err {
            return None;
        }

        let fd = match self.map.fd() {
            Ok(fd) => fd,
            Err(e) => {
                self.err = true;
                return Some(Err(e));
            }
        };

        match bpf_map_get_next_key(fd, self.key.as_ref()) {
            Ok(Some(key)) => {
                self.key = Some(key);
                return Some(Ok(key));
            }
            Ok(None) => {
                self.key = None;
                return None;
            }
            Err((code, io_error)) => {
                self.err = true;
                return Some(Err(MapError::GetNextKeyFailed { code, io_error }));
            }
        }
    }
}

pub struct MapIter<'coll, K: Pod, V: Pod> {
    inner: MapKeys<'coll, K, V>,
}

impl<'coll, K: Pod, V: Pod> MapIter<'coll, K, V> {
    fn new(map: &'coll dyn IterableMap<K, V>) -> MapIter<'coll, K, V> {
        MapIter {
            inner: MapKeys::new(map),
        }
    }
}

impl<K: Pod, V: Pod> Iterator for MapIter<'_, K, V> {
    type Item = Result<(K, V), MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.inner.next() {
                Some(Ok(key)) => {
                    let value = unsafe { self.inner.map.get(&key) };
                    match value {
                        Ok(None) => continue,
                        Ok(Some(value)) => return Some(Ok((key, value))),
                        Err(e) => return Some(Err(e)),
                    }
                }
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
        }
    }
}

impl AsRef<Map> for &Map {
    fn as_ref(&self) -> &Map {
        self
    }
}

impl AsRef<Map> for &mut Map {
    fn as_ref(&self) -> &Map {
        self
    }
}

impl AsMut<Map> for &mut Map {
    fn as_mut(&mut self) -> &mut Map {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use libc::{EFAULT, ENOENT};

    use crate::{
        bpf_map_def,
        generated::{
            bpf_attr, bpf_cmd,
            bpf_map_type::{BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERF_EVENT_ARRAY},
        },
        obj,
        syscalls::{override_syscall, SysResult, Syscall},
    };

    use super::*;

    fn new_obj_map(name: &str) -> obj::Map {
        obj::Map {
            name: name.to_string(),
            def: bpf_map_def {
                map_type: BPF_MAP_TYPE_HASH,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                map_flags: 0,
            },
            section_index: 0,
            data: Vec::new(),
        }
    }

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_key_size() {
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        assert!(matches!(
            HashMap::<_, u8, u32>::new(&map),
            Err(MapError::InvalidKeySize {
                size: 1,
                expected: 4
            })
        ));
    }

    #[test]
    fn test_wrong_value_size() {
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        assert!(matches!(
            HashMap::<_, u32, u16>::new(&map),
            Err(MapError::InvalidValueSize {
                size: 2,
                expected: 4
            })
        ));
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = Map {
            obj: obj::Map {
                name: "TEST".to_string(),
                def: bpf_map_def {
                    map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                    key_size: 4,
                    value_size: 4,
                    max_entries: 1024,
                    map_flags: 0,
                },
                section_index: 0,
                data: Vec::new(),
            },
            fd: None,
        };

        assert!(matches!(
            HashMap::<_, u32, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        ));
    }

    #[test]
    fn test_try_from_ok() {
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        assert!(HashMap::<_, u32, u32>::try_from(&map).is_ok())
    }

    #[test]
    fn test_insert_not_created() {
        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(
            hm.insert(1, 42, 0),
            Err(MapError::NotCreated { .. })
        ));
    }

    #[test]
    fn test_insert_syscall_error() {
        override_syscall(|_| sys_error(EFAULT));

        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(
            hm.insert(1, 42, 0),
            Err(MapError::UpdateElementFailed { code: -1, io_error }) if io_error.raw_os_error() == Some(EFAULT)
        ));
    }

    #[test]
    fn test_insert_ok() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(1),
            _ => sys_error(EFAULT),
        });

        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(hm.insert(1, 42, 0).is_ok());
    }

    #[test]
    fn test_remove_not_created() {
        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(hm.remove(&1), Err(MapError::NotCreated { .. })));
    }

    #[test]
    fn test_remove_syscall_error() {
        override_syscall(|_| sys_error(EFAULT));

        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(
            hm.remove(&1),
            Err(MapError::DeleteElementFailed { code: -1, io_error }) if io_error.raw_os_error() == Some(EFAULT)
        ));
    }

    #[test]
    fn test_remove_ok() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_DELETE_ELEM,
                ..
            } => Ok(1),
            _ => sys_error(EFAULT),
        });

        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(hm.remove(&1).is_ok());
    }

    #[test]
    fn test_get_not_created() {
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        assert!(matches!(
            unsafe { hm.get(&1, 0) },
            Err(MapError::NotCreated { .. })
        ));
    }

    #[test]
    fn test_get_syscall_error() {
        override_syscall(|_| sys_error(EFAULT));
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        assert!(matches!(
            unsafe { hm.get(&1, 0) },
            Err(MapError::LookupElementFailed { code: -1, io_error }) if io_error.raw_os_error() == Some(EFAULT)
        ));
    }

    #[test]
    fn test_get_not_found() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        assert!(matches!(unsafe { hm.get(&1, 0) }, Ok(None)));
    }

    #[test]
    fn test_pop_not_created() {
        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: None,
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(
            unsafe { hm.pop(&1) },
            Err(MapError::NotCreated { .. })
        ));
    }

    #[test]
    fn test_pop_syscall_error() {
        override_syscall(|_| sys_error(EFAULT));
        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(
            unsafe { hm.pop(&1) },
            Err(MapError::LookupAndDeleteElementFailed { code: -1, io_error }) if io_error.raw_os_error() == Some(EFAULT)
        ));
    }

    #[test]
    fn test_pop_not_found() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });
        let mut map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let mut hm = HashMap::<_, u32, u32>::new(&mut map).unwrap();

        assert!(matches!(unsafe { hm.pop(&1) }, Ok(None)));
    }

    fn bpf_key<T: Copy>(attr: &bpf_attr) -> Option<T> {
        match unsafe { attr.__bindgen_anon_2.key } as *const T {
            p if p.is_null() => None,
            p => Some(unsafe { *p }),
        }
    }

    fn set_next_key<T: Copy>(attr: &bpf_attr, next: T) {
        let key = unsafe { attr.__bindgen_anon_2.__bindgen_anon_1.next_key } as *const T as *mut T;
        unsafe { *key = next };
    }

    fn set_ret<T: Copy>(attr: &bpf_attr, ret: T) {
        let value = unsafe { attr.__bindgen_anon_2.__bindgen_anon_1.value } as *const T as *mut T;
        unsafe { *value = ret };
    }

    #[test]
    fn test_keys_empty() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();
        let keys = unsafe { hm.keys() }.collect::<Result<Vec<_>, _>>();
        assert!(matches!(keys, Ok(ks) if ks.is_empty()))
    }

    fn get_next_key(attr: &bpf_attr) -> SysResult {
        match bpf_key(&attr) {
            None => set_next_key(&attr, 10),
            Some(10) => set_next_key(&attr, 20),
            Some(20) => set_next_key(&attr, 30),
            Some(30) => return sys_error(ENOENT),
            Some(_) => return sys_error(EFAULT),
        };

        Ok(1)
    }

    fn lookup_elem(attr: &bpf_attr) -> SysResult {
        match bpf_key(&attr) {
            Some(10) => set_ret(&attr, 100),
            Some(20) => set_ret(&attr, 200),
            Some(30) => set_ret(&attr, 300),
            Some(_) => return sys_error(ENOENT),
            None => return sys_error(EFAULT),
        };

        Ok(1)
    }

    #[test]
    fn test_keys() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(&attr),
            _ => sys_error(EFAULT),
        });

        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let keys = unsafe { hm.keys() }.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(&keys, &[10, 20, 30])
    }

    #[test]
    fn test_keys_error() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => {
                match bpf_key(&attr) {
                    None => set_next_key(&attr, 10),
                    Some(10) => set_next_key(&attr, 20),
                    Some(_) => return sys_error(EFAULT),
                };

                Ok(1)
            }
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let mut keys = unsafe { hm.keys() };
        assert!(matches!(keys.next(), Some(Ok(10))));
        assert!(matches!(keys.next(), Some(Ok(20))));
        assert!(matches!(
            keys.next(),
            Some(Err(MapError::GetNextKeyFailed { .. }))
        ));
        assert!(matches!(keys.next(), None));
    }

    #[test]
    fn test_iter() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(&attr),
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => lookup_elem(&attr),
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();
        let items = unsafe { hm.iter() }.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(&items, &[(10, 100), (20, 200), (30, 300)])
    }

    #[test]
    fn test_iter_key_deleted() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(&attr),
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => {
                match bpf_key(&attr) {
                    Some(10) => set_ret(&attr, 100),
                    Some(20) => return sys_error(ENOENT),
                    Some(30) => set_ret(&attr, 300),
                    Some(_) => return sys_error(ENOENT),
                    None => return sys_error(EFAULT),
                };

                Ok(1)
            }
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let items = unsafe { hm.iter() }.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(&items, &[(10, 100), (30, 300)])
    }

    #[test]
    fn test_iter_key_error() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => {
                match bpf_key(&attr) {
                    None => set_next_key(&attr, 10),
                    Some(10) => set_next_key(&attr, 20),
                    Some(20) => return sys_error(EFAULT),
                    Some(30) => return sys_error(ENOENT),
                    Some(_) => panic!(),
                };

                Ok(1)
            }
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => lookup_elem(&attr),
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let mut iter = unsafe { hm.iter() };
        assert!(matches!(iter.next(), Some(Ok((10, 100)))));
        assert!(matches!(iter.next(), Some(Ok((20, 200)))));
        assert!(matches!(
            iter.next(),
            Some(Err(MapError::GetNextKeyFailed { .. }))
        ));
        assert!(matches!(iter.next(), None));
    }

    #[test]
    fn test_iter_value_error() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                attr,
            } => get_next_key(&attr),
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                attr,
            } => {
                match bpf_key(&attr) {
                    Some(10) => set_ret(&attr, 100),
                    Some(20) => return sys_error(EFAULT),
                    Some(30) => set_ret(&attr, 300),
                    Some(_) => return sys_error(ENOENT),
                    None => return sys_error(EFAULT),
                };

                Ok(1)
            }
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map("TEST"),
            fd: Some(42),
        };
        let hm = HashMap::<_, u32, u32>::new(&map).unwrap();

        let mut iter = unsafe { hm.iter() };
        assert!(matches!(iter.next(), Some(Ok((10, 100)))));
        assert!(matches!(
            iter.next(),
            Some(Err(MapError::LookupElementFailed { .. }))
        ));
        assert!(matches!(iter.next(), Some(Ok((30, 300)))));
        assert!(matches!(iter.next(), None));
    }
}
