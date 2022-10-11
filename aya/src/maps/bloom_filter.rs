//! A Bloom Filter.
use std::{marker::PhantomData, ops::Deref};

use core::mem;

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER,
    maps::{Map, MapError, MapRef, MapRefMut},
    sys::{bpf_map_lookup_elem_ptr, bpf_map_push_elem},
    Pod,
};

/// A Bloom Filter.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.16.
///
/// # Examples
///
/// ```no_run
/// # let bpf = aya::Bpf::load(&[])?;
/// use aya::maps::bloom_filter::BloomFilter;
///
/// let mut bloom_filter = BloomFilter::try_from(bpf.map_mut("BLOOM_FILTER")?)?;
///
/// bloom_filter.insert(1, 0)?;
///
/// assert!(bloom_filter.contains(&1, 0).is_ok());
/// assert!(bloom_filter.contains(&2, 0).is_err());
///
/// # Ok::<(), aya::BpfError>(())
/// ```

#[doc(alias = "BPF_MAP_TYPE_BLOOM_FILTER")]
pub struct BloomFilter<T: Deref<Target = Map>, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: Deref<Target = Map>, V: Pod> BloomFilter<T, V> {
    pub(crate) fn new(map: T) -> Result<BloomFilter<T, V>, MapError> {
        let map_type = map.obj.map_type();

        // validate the map definition
        if map_type != BPF_MAP_TYPE_BLOOM_FILTER as u32 {
            return Err(MapError::InvalidMapType { map_type });
        }

        let size = mem::size_of::<V>();
        let expected = map.obj.value_size() as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        };

        let _ = map.fd_or_err()?;

        Ok(BloomFilter {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Query the existence of the element.
    pub fn contains(&self, mut value: &V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.deref().fd_or_err()?;

        bpf_map_lookup_elem_ptr::<u32, _>(fd, None, &mut value, flags)
            .map_err(|(_, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            })?
            .ok_or(MapError::ElementNotFound)?;
        Ok(())
    }

    /// Inserts a value into the map.
    pub fn insert(&self, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        bpf_map_push_elem(fd, &value, flags).map_err(|(_, io_error)| MapError::SyscallError {
            call: "bpf_map_push_elem".to_owned(),
            io_error,
        })?;
        Ok(())
    }
}

impl<V: Pod> TryFrom<MapRef> for BloomFilter<MapRef, V> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<BloomFilter<MapRef, V>, MapError> {
        BloomFilter::new(a)
    }
}

impl<V: Pod> TryFrom<MapRefMut> for BloomFilter<MapRefMut, V> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<BloomFilter<MapRefMut, V>, MapError> {
        BloomFilter::new(a)
    }
}

impl<'a, V: Pod> TryFrom<&'a Map> for BloomFilter<&'a Map, V> {
    type Error = MapError;

    fn try_from(a: &'a Map) -> Result<BloomFilter<&'a Map, V>, MapError> {
        BloomFilter::new(a)
    }
}

impl<'a, V: Pod> TryFrom<&'a mut Map> for BloomFilter<&'a mut Map, V> {
    type Error = MapError;

    fn try_from(a: &'a mut Map) -> Result<BloomFilter<&'a mut Map, V>, MapError> {
        BloomFilter::new(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bpf_map_def,
        generated::{
            bpf_cmd,
            bpf_map_type::{BPF_MAP_TYPE_BLOOM_FILTER, BPF_MAP_TYPE_PERF_EVENT_ARRAY},
        },
        obj,
        sys::{override_syscall, SysResult, Syscall},
    };
    use libc::{EFAULT, ENOENT};
    use std::io;

    fn new_obj_map() -> obj::Map {
        obj::Map::Legacy(obj::LegacyMap {
            def: bpf_map_def {
                map_type: BPF_MAP_TYPE_BLOOM_FILTER as u32,
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                ..Default::default()
            },
            section_index: 0,
            symbol_index: 0,
            data: Vec::new(),
            kind: obj::MapKind::Other,
        })
    }

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_value_size() {
        let map = Map {
            obj: new_obj_map(),
            fd: None,
            pinned: false,
            btf_fd: None,
        };
        assert!(matches!(
            BloomFilter::<_, u16>::new(&map),
            Err(MapError::InvalidValueSize {
                size: 2,
                expected: 4
            })
        ));
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = Map {
            obj: obj::Map::Legacy(obj::LegacyMap {
                def: bpf_map_def {
                    map_type: BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32,
                    key_size: 4,
                    value_size: 4,
                    max_entries: 1024,
                    ..Default::default()
                },
                section_index: 0,
                symbol_index: 0,
                data: Vec::new(),
                kind: obj::MapKind::Other,
            }),
            fd: None,
            pinned: false,
            btf_fd: None,
        };

        assert!(matches!(
            BloomFilter::<_, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        ));
    }

    #[test]
    fn test_new_not_created() {
        let mut map = Map {
            obj: new_obj_map(),
            fd: None,
            pinned: false,
            btf_fd: None,
        };

        assert!(matches!(
            BloomFilter::<_, u32>::new(&mut map),
            Err(MapError::NotCreated { .. })
        ));
    }

    #[test]
    fn test_new_ok() {
        let mut map = Map {
            obj: new_obj_map(),
            fd: Some(42),
            pinned: false,
            btf_fd: None,
        };

        assert!(BloomFilter::<_, u32>::new(&mut map).is_ok());
    }

    #[test]
    fn test_try_from_ok() {
        let map = Map {
            obj: new_obj_map(),
            fd: Some(42),
            pinned: false,
            btf_fd: None,
        };
        assert!(BloomFilter::<_, u32>::try_from(&map).is_ok())
    }

    #[test]
    fn test_insert_syscall_error() {
        override_syscall(|_| sys_error(EFAULT));

        let mut map = Map {
            obj: new_obj_map(),
            fd: Some(42),
            pinned: false,
            btf_fd: None,
        };
        let bloom_filter = BloomFilter::<_, u32>::new(&mut map).unwrap();

        assert!(matches!(
            bloom_filter.insert(1, 0),
            Err(MapError::SyscallError { call, io_error }) if call == "bpf_map_push_elem" && io_error.raw_os_error() == Some(EFAULT)
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
            obj: new_obj_map(),
            fd: Some(42),
            pinned: false,
            btf_fd: None,
        };

        let bloom_filter = BloomFilter::<_, u32>::new(&mut map).unwrap();
        assert!(bloom_filter.insert(0, 42).is_ok());
    }

    #[test]
    fn test_contains_syscall_error() {
        override_syscall(|_| sys_error(EFAULT));
        let map = Map {
            obj: new_obj_map(),
            fd: Some(42),
            pinned: false,
            btf_fd: None,
        };
        let bloom_filter = BloomFilter::<_, u32>::new(&map).unwrap();

        assert!(matches!(
            bloom_filter.contains(&1, 0),
            Err(MapError::SyscallError { call, io_error }) if call == "bpf_map_lookup_elem" && io_error.raw_os_error() == Some(EFAULT)
        ));
    }

    #[test]
    fn test_contains_not_found() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });
        let map = Map {
            obj: new_obj_map(),
            fd: Some(42),
            pinned: false,
            btf_fd: None,
        };
        let bloom_filter = BloomFilter::<_, u32>::new(&map).unwrap();

        assert!(matches!(
            bloom_filter.contains(&1, 0),
            Err(MapError::ElementNotFound)
        ));
    }
}
