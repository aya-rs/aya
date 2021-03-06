//! eBPF map types.
//!
//! The eBPF platform provides data structures - maps in eBPF speak - that can be used by eBPF
//! programs and user-space to exchange data.
//!
//! When you call [Bpf::load_file](crate::Bpf::load_file) or [Bpf::load](crate::Bpf::load), aya
//! transparently discovers all the maps defined in the loaded code and initializes them. The maps
//! can then be accessed using [Bpf::map](crate::Bpf::map) and [Bpf::map_mut](crate::Bpf::map_mut).
//!
//! # Concrete map types
//!
//! Different map types support different operations. [Bpf::map](crate::Bpf::map) and
//! [Bpf::map_mut](crate::Bpf::map_mut) always return the opaque [MapRef] and [MapRefMut] types
//! respectively, which you can convert those to concrete map types using the
//! [TryFrom](std::convert::TryFrom) trait. For example to insert a value inside a
//! [HashMap](crate::maps::hash_map::HashMap):
//!
//! ```no_run
//! # let bpf = aya::Bpf::load(&[], None)?;
//! use aya::maps::HashMap;
//! use std::convert::TryFrom;
//!
//! const CONFIG_KEY_NUM_RETRIES: u8 = 1;
//!
//! let mut hm = HashMap::try_from(bpf.map_mut("CONFIG")?)?;
//! hm.insert(CONFIG_KEY_NUM_RETRIES, 3, 0 /* flags */);
//! # Ok::<(), aya::BpfError>(())
//! ```
//!
//! All the concrete map types implement the [TryFrom](std::convert::TryFrom) trait.
use std::{convert::TryFrom, ffi::CString, io, os::unix::io::RawFd};
use thiserror::Error;

use crate::{
    generated::bpf_map_type,
    obj,
    sys::{bpf_create_map, bpf_map_get_next_key},
    Pod,
};

pub mod hash_map;
mod map_lock;
pub mod perf_map;
pub mod program_array;

pub use hash_map::HashMap;
pub use map_lock::*;
pub use perf_map::PerfMap;
pub use program_array::ProgramArray;

#[derive(Error, Debug)]
pub enum MapError {
    #[error("map `{name}` not found ")]
    NotFound { name: String },

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

    #[error("the `{call}` syscall failed with code {code} io_error {io_error}")]
    SyscallError {
        call: String,
        code: i64,
        io_error: io::Error,
    },

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

    pub fn name(&self) -> &str {
        &self.obj.name
    }

    pub fn map_type(&self) -> Result<bpf_map_type, MapError> {
        bpf_map_type::try_from(self.obj.def.map_type)
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

/// Iterator returned by `map.keys()`.
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
                return Some(Err(MapError::SyscallError {
                    call: "bpf_map_get_next_key".to_owned(),
                    code,
                    io_error,
                }));
            }
        }
    }
}

/// Iterator returned by `map.iter()`.
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

impl TryFrom<u32> for bpf_map_type {
    type Error = MapError;

    fn try_from(map_type: u32) -> Result<Self, Self::Error> {
        use bpf_map_type::*;
        Ok(match map_type {
            x if x == BPF_MAP_TYPE_UNSPEC as u32 => BPF_MAP_TYPE_UNSPEC,
            x if x == BPF_MAP_TYPE_HASH as u32 => BPF_MAP_TYPE_HASH,
            x if x == BPF_MAP_TYPE_ARRAY as u32 => BPF_MAP_TYPE_ARRAY,
            x if x == BPF_MAP_TYPE_PROG_ARRAY as u32 => BPF_MAP_TYPE_PROG_ARRAY,
            x if x == BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 => BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_HASH as u32 => BPF_MAP_TYPE_PERCPU_HASH,
            x if x == BPF_MAP_TYPE_PERCPU_ARRAY as u32 => BPF_MAP_TYPE_PERCPU_ARRAY,
            x if x == BPF_MAP_TYPE_STACK_TRACE as u32 => BPF_MAP_TYPE_STACK_TRACE,
            x if x == BPF_MAP_TYPE_CGROUP_ARRAY as u32 => BPF_MAP_TYPE_CGROUP_ARRAY,
            x if x == BPF_MAP_TYPE_LRU_HASH as u32 => BPF_MAP_TYPE_LRU_HASH,
            x if x == BPF_MAP_TYPE_LRU_PERCPU_HASH as u32 => BPF_MAP_TYPE_LRU_PERCPU_HASH,
            x if x == BPF_MAP_TYPE_LPM_TRIE as u32 => BPF_MAP_TYPE_LPM_TRIE,
            x if x == BPF_MAP_TYPE_ARRAY_OF_MAPS as u32 => BPF_MAP_TYPE_ARRAY_OF_MAPS,
            x if x == BPF_MAP_TYPE_HASH_OF_MAPS as u32 => BPF_MAP_TYPE_HASH_OF_MAPS,
            x if x == BPF_MAP_TYPE_DEVMAP as u32 => BPF_MAP_TYPE_DEVMAP,
            x if x == BPF_MAP_TYPE_SOCKMAP as u32 => BPF_MAP_TYPE_SOCKMAP,
            x if x == BPF_MAP_TYPE_CPUMAP as u32 => BPF_MAP_TYPE_CPUMAP,
            x if x == BPF_MAP_TYPE_XSKMAP as u32 => BPF_MAP_TYPE_XSKMAP,
            x if x == BPF_MAP_TYPE_SOCKHASH as u32 => BPF_MAP_TYPE_SOCKHASH,
            x if x == BPF_MAP_TYPE_CGROUP_STORAGE as u32 => BPF_MAP_TYPE_CGROUP_STORAGE,
            x if x == BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as u32 => BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            x if x == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE as u32 => {
                BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
            }
            x if x == BPF_MAP_TYPE_QUEUE as u32 => BPF_MAP_TYPE_QUEUE,
            x if x == BPF_MAP_TYPE_STACK as u32 => BPF_MAP_TYPE_STACK,
            x if x == BPF_MAP_TYPE_SK_STORAGE as u32 => BPF_MAP_TYPE_SK_STORAGE,
            x if x == BPF_MAP_TYPE_DEVMAP_HASH as u32 => BPF_MAP_TYPE_DEVMAP_HASH,
            x if x == BPF_MAP_TYPE_STRUCT_OPS as u32 => BPF_MAP_TYPE_STRUCT_OPS,
            x if x == BPF_MAP_TYPE_RINGBUF as u32 => BPF_MAP_TYPE_RINGBUF,
            x if x == BPF_MAP_TYPE_INODE_STORAGE as u32 => BPF_MAP_TYPE_INODE_STORAGE,
            x if x == BPF_MAP_TYPE_TASK_STORAGE as u32 => BPF_MAP_TYPE_TASK_STORAGE,
            _ => return Err(MapError::InvalidMapType { map_type }),
        })
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
                map_type: BPF_MAP_TYPE_HASH as u32,
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
