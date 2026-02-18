//! An array of eBPF maps.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    maps::{FromMapData, InnerMap, MapData, MapError, check_bounds, check_kv_size},
    sys::{SyscallError, bpf_map_lookup_elem, bpf_map_update_elem},
};

/// An array of eBPF maps.
///
/// An `ArrayOfMaps` stores references to other eBPF maps.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.12.
#[doc(alias = "BPF_MAP_TYPE_ARRAY_OF_MAPS")]
#[derive(Debug)]
pub struct ArrayOfMaps<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> ArrayOfMaps<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, u32>(data)?;
        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().obj.max_entries()
    }

    /// Returns true if the array is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the inner map stored at the given index.
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
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get<M: FromMapData>(&self, index: &u32, flags: u64) -> Result<M, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, *index)?;
        let fd = data.fd().as_fd();

        let value: Option<u32> =
            bpf_map_lookup_elem(fd, index, flags).map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        match value {
            Some(id) => super::map_from_id(id),
            None => Err(MapError::KeyNotFound),
        }
    }
}

impl<T: BorrowMut<MapData>> ArrayOfMaps<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: &impl InnerMap, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        let fd = data.fd().as_fd();
        bpf_map_update_elem(fd, Some(&index), &value.fd().as_fd().as_raw_fd(), flags).map_err(
            |io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            },
        )?;
        Ok(())
    }
}

impl ArrayOfMaps<MapData> {
    /// Returns a reference to the underlying [`MapData`].
    pub const fn map_data(&self) -> &MapData {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use assert_matches::assert_matches;
    use aya_obj::generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS};
    use libc::{EFAULT, ENOENT};

    use super::*;
    use crate::{
        maps::{Map, test_utils},
        sys::{SysResult, Syscall, override_syscall},
    };

    fn new_obj_map() -> aya_obj::Map {
        test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_ARRAY_OF_MAPS)
    }

    fn new_map(obj: aya_obj::Map) -> MapData {
        test_utils::new_map(obj)
    }

    fn sys_error(value: i32) -> SysResult {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_key_size() {
        let map = new_map(test_utils::new_obj_map::<u8>(BPF_MAP_TYPE_ARRAY_OF_MAPS));
        assert_matches!(
            ArrayOfMaps::new(&map),
            Err(MapError::InvalidKeySize {
                size: 4,
                expected: 1
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
            ArrayOfMaps::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        ArrayOfMaps::new(&map).unwrap();
    }

    #[test]
    fn test_set_syscall_error() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        ));
        let mut arr = ArrayOfMaps::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            arr.set(0, &inner_map, 0),
            Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_update_elem",
                ..
            }))
        );
    }

    #[test]
    fn test_set_ok() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        ));
        let mut arr = ArrayOfMaps::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        arr.set(0, &inner_map, 0).unwrap();
    }

    #[test]
    fn test_set_out_of_bounds() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        ));
        let mut arr = ArrayOfMaps::new(&mut map).unwrap();

        assert_matches!(
            arr.set(1024, &inner_map, 0),
            Err(MapError::OutOfBounds { .. })
        );
    }

    #[test]
    fn test_get_syscall_error() {
        let map = new_map(new_obj_map());
        let arr = ArrayOfMaps::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            arr.get::<crate::maps::HashMap<MapData, u32, u32>>(&0, 0),
            Err(MapError::SyscallError(SyscallError {
                call: "bpf_map_lookup_elem",
                ..
            }))
        );
    }

    #[test]
    fn test_get_not_found() {
        let map = new_map(new_obj_map());
        let arr = ArrayOfMaps::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        assert_matches!(
            arr.get::<crate::maps::HashMap<MapData, u32, u32>>(&0, 0),
            Err(MapError::KeyNotFound)
        );
    }

    #[test]
    fn test_get_out_of_bounds() {
        let map = new_map(new_obj_map());
        let arr = ArrayOfMaps::new(&map).unwrap();

        assert_matches!(
            arr.get::<crate::maps::HashMap<MapData, u32, u32>>(&1024, 0),
            Err(MapError::OutOfBounds { .. })
        );
    }
}
