//! A Bloom Filter.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    maps::{check_v_size, MapData, MapError},
    sys::{bpf_map_lookup_elem_ptr, bpf_map_push_elem, SyscallError},
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
/// # use assert_matches::assert_matches;
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::MapError;
/// use aya::maps::bloom_filter::BloomFilter;
///
/// let mut bloom_filter = BloomFilter::try_from(bpf.map_mut("BLOOM_FILTER").unwrap())?;
///
/// bloom_filter.insert(1, 0)?;
///
/// assert_matches!(bloom_filter.contains(&1, 0), Ok(()));
/// assert_matches!(bloom_filter.contains(&2, 0), Err(MapError::ElementNotFound));
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_BLOOM_FILTER")]
#[derive(Debug)]
pub struct BloomFilter<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> BloomFilter<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_v_size::<V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Query the existence of the element.
    pub fn contains(&self, mut value: &V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.borrow().fd().as_fd();

        match bpf_map_lookup_elem_ptr::<u32, _>(fd, None, &mut value, flags).map_err(
            |io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            },
        )? {
            None => Err(MapError::ElementNotFound),
            Some(()) => Ok(()),
        }
    }
}

impl<T: BorrowMut<MapData>, V: Pod> BloomFilter<T, V> {
    /// Inserts a value into the map.
    pub fn insert(&mut self, value: impl Borrow<V>, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.borrow_mut().fd().as_fd();
        bpf_map_push_elem(fd, value.borrow(), flags)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_push_elem",
                io_error,
            })
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::c_long, io};

    use assert_matches::assert_matches;
    use aya_obj::generated::{
        bpf_cmd,
        bpf_map_type::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_BLOOM_FILTER},
    };
    use libc::{EFAULT, ENOENT};

    use super::*;
    use crate::{
        maps::{
            test_utils::{self, new_map},
            Map,
        },
        sys::{override_syscall, SysResult, Syscall},
    };

    fn new_obj_map() -> aya_obj::Map {
        test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_BLOOM_FILTER)
    }

    fn sys_error(value: i32) -> SysResult<c_long> {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_value_size() {
        let map = new_map(new_obj_map());
        assert_matches!(
            BloomFilter::<_, u16>::new(&map),
            Err(MapError::InvalidValueSize {
                size: 2,
                expected: 4
            })
        );
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = new_map(test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_ARRAY));
        let map = Map::Array(map);

        assert_matches!(
            BloomFilter::<_, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());

        let _: BloomFilter<_, u32> = BloomFilter::new(&map).unwrap();
    }

    #[test]
    fn test_try_from_ok() {
        let map = new_map(new_obj_map());

        let map = Map::BloomFilter(map);
        let _: BloomFilter<_, u32> = map.try_into().unwrap();
    }

    #[test]
    fn test_insert_syscall_error() {
        let mut map = new_map(new_obj_map());
        let mut bloom_filter = BloomFilter::<_, u32>::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            bloom_filter.insert(1, 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_push_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_insert_ok() {
        let mut map = new_map(new_obj_map());
        let mut bloom_filter = BloomFilter::<_, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert_matches!(bloom_filter.insert(0, 42), Ok(()));
    }

    #[test]
    fn test_contains_syscall_error() {
        let map = new_map(new_obj_map());
        let bloom_filter = BloomFilter::<_, u32>::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            bloom_filter.contains(&1, 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_lookup_elem", io_error })) if io_error.raw_os_error() == Some(EFAULT)
        );
    }

    #[test]
    fn test_contains_not_found() {
        let map = new_map(new_obj_map());
        let bloom_filter = BloomFilter::<_, u32>::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        assert_matches!(bloom_filter.contains(&1, 0), Err(MapError::ElementNotFound));
    }
}
