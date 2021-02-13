use std::{ffi::CString, io};
use thiserror::Error;

use crate::{
    obj,
    sys::{bpf_create_map, bpf_map_get_next_key},
    Pod, RawFd,
};

mod hash_map;
mod map_lock;
pub mod perf_map;
mod program_array;

pub use hash_map::*;
pub use map_lock::*;
pub use perf_map::PerfMap;
pub use program_array::*;

#[derive(Error, Debug)]
pub enum MapError {
    #[error("invalid map type {map_type}")]
    InvalidMapType { map_type: u32 },

    #[error("invalid map name `{name}`")]
    InvalidName { name: String },

    #[error("the map `{name}` has not been created")]
    NotCreated { name: String },

    #[error("the map `{name}` has already been created")]
    AlreadyCreated { name: String },

    #[error("failed to create map `{name}`: {code}")]
    CreateError {
        name: String,
        code: i64,
        io_error: io::Error,
    },

    #[error("invalid key size {size}, expected {expected}")]
    InvalidKeySize { size: usize, expected: usize },

    #[error("invalid value size {size}, expected {expected}")]
    InvalidValueSize { size: usize, expected: usize },

    #[error("the index is {index} but `max_entries` is {max_entries}")]
    OutOfBounds { index: u32, max_entries: u32 },

    #[error("the program is not loaded")]
    ProgramNotLoaded,

    #[error("the BPF_MAP_UPDATE_ELEM syscall failed with code {code} io_error {io_error}")]
    UpdateElementError { code: i64, io_error: io::Error },

    #[error("the BPF_MAP_LOOKUP_ELEM syscall failed with code {code} io_error {io_error}")]
    LookupElementError { code: i64, io_error: io::Error },

    #[error("the BPF_MAP_DELETE_ELEM syscall failed with code {code} io_error {io_error}")]
    DeleteElementError { code: i64, io_error: io::Error },

    #[error(
        "the BPF_MAP_LOOKUP_AND_DELETE_ELEM syscall failed with code {code} io_error {io_error}"
    )]
    LookupAndDeleteElementError { code: i64, io_error: io::Error },

    #[error("the BPF_MAP_GET_NEXT_KEY syscall failed with code {code} io_error {io_error}")]
    GetNextKeyError { code: i64, io_error: io::Error },

    #[error("map `{name}` is borrowed mutably")]
    BorrowError { name: String },

    #[error("map `{name}` is already borrowed")]
    BorrowMutError { name: String },
}

#[derive(Debug)]
pub struct Map {
    pub(crate) obj: obj::Map,
    pub(crate) fd: Option<RawFd>,
}

impl Map {
    pub fn create(&mut self) -> Result<RawFd, MapError> {
        let name = self.obj.name.clone();
        if self.fd.is_some() {
            return Err(MapError::AlreadyCreated { name: name.clone() });
        }

        let c_name =
            CString::new(name.clone()).map_err(|_| MapError::InvalidName { name: name.clone() })?;

        let fd = bpf_create_map(&c_name, &self.obj.def).map_err(|(code, io_error)| {
            MapError::CreateError {
                name,
                code,
                io_error,
            }
        })? as RawFd;

        self.fd = Some(fd);

        Ok(fd)
    }

    pub(crate) fn fd_or_err(&self) -> Result<RawFd, MapError> {
        self.fd.ok_or_else(|| MapError::NotCreated {
            name: self.obj.name.clone(),
        })
    }
}

pub(crate) trait IterableMap<K: Pod, V: Pod> {
    fn fd(&self) -> Result<RawFd, MapError>;
    unsafe fn get(&self, key: &K) -> Result<Option<V>, MapError>;
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
                return Some(Err(MapError::GetNextKeyError { code, io_error }));
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

#[cfg(test)]
mod tests {
    use libc::EFAULT;

    use crate::{
        bpf_map_def,
        generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_HASH},
        sys::{override_syscall, Syscall},
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

    fn new_map(name: &str) -> Map {
        Map {
            obj: new_obj_map(name),
            fd: None,
        }
    }

    #[test]
    fn test_create() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(42),
            _ => Err((-1, io::Error::from_raw_os_error(EFAULT))),
        });

        let mut map = new_map("foo");
        assert!(matches!(map.create(), Ok(42)));
        assert_eq!(map.fd, Some(42));
        assert!(matches!(map.create(), Err(MapError::AlreadyCreated { .. })));
    }

    #[test]
    fn test_create_failed() {
        override_syscall(|_| {
            return Err((-42, io::Error::from_raw_os_error(EFAULT)));
        });

        let mut map = new_map("foo");
        let ret = map.create();
        assert!(matches!(ret, Err(MapError::CreateError { .. })));
        if let Err(MapError::CreateError {
            name,
            code,
            io_error,
        }) = ret
        {
            assert_eq!(name, "foo");
            assert_eq!(code, -42);
            assert_eq!(io_error.raw_os_error(), Some(EFAULT));
        }
        assert_eq!(map.fd, None);
    }
}
