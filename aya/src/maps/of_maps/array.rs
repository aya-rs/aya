//! An array of eBPF maps.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::{AsFd as _, AsRawFd as _},
};

use crate::{
    Pod,
    maps::{MapData, MapError, MapFd, check_bounds, check_kv_size, info::MapInfo},
    sys::{SyscallError, bpf_map_get_fd_by_id, bpf_map_lookup_elem, bpf_map_update_elem},
};

/// An array of eBPF Maps
///
/// A `Array` is used to store references to other maps.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
#[doc(alias = "BPF_MAP_TYPE_ARRAY_OF_MAPS")]
#[derive(Debug)]
pub struct Array<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> Array<T> {
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
    /// The returned map can be used to read and write values. If you only need
    /// the file descriptor, you can call `.fd()` on the returned map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get<V: Pod>(
        &self,
        index: &u32,
        flags: u64,
    ) -> Result<crate::maps::Array<MapData, V>, MapError> {
        let data = self.inner.borrow();
        check_bounds(data, *index)?;
        let fd = data.fd().as_fd();

        let value: Option<u32> =
            bpf_map_lookup_elem(fd, index, flags).map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        if let Some(id) = value {
            let inner_fd = bpf_map_get_fd_by_id(id)?;
            let info = MapInfo::new_from_fd(inner_fd.as_fd())?;
            let map_data = MapData::from_id(info.id())?;
            crate::maps::Array::new(map_data)
        } else {
            Err(MapError::KeyNotFound)
        }
    }

    /// An iterator over the elements of the array. The iterator item type is
    /// `Result<(u32, Array<MapData, V>), MapError>`.
    pub fn iter<V: Pod>(&self) -> ArrayOfMapsIter<'_, T, V> {
        ArrayOfMapsIter::new(self)
    }
}

/// Iterator over an ArrayOfMaps.
pub struct ArrayOfMapsIter<'coll, T, V: Pod> {
    map: &'coll Array<T>,
    index: u32,
    len: u32,
    _v: PhantomData<V>,
}

impl<'coll, T: Borrow<MapData>, V: Pod> ArrayOfMapsIter<'coll, T, V> {
    fn new(map: &'coll Array<T>) -> Self {
        Self {
            map,
            index: 0,
            len: map.len(),
            _v: PhantomData,
        }
    }
}

impl<T: Borrow<MapData>, V: Pod> Iterator for ArrayOfMapsIter<'_, T, V> {
    type Item = Result<(u32, crate::maps::Array<MapData, V>), MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.len {
            let index = self.index;
            self.index += 1;
            match self.map.get::<V>(&index, 0) {
                Ok(inner_map) => return Some(Ok((index, inner_map))),
                Err(MapError::KeyNotFound) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }
}
impl<T: BorrowMut<MapData>> Array<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: &MapFd, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        let fd = data.fd().as_fd();
        bpf_map_update_elem(fd, Some(&index), &value.as_fd().as_raw_fd(), flags).map_err(
            |io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            },
        )?;
        Ok(())
    }
}

impl Array<MapData> {
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
            Array::new(&map),
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
            Array::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        assert!(Array::new(&map).is_ok());
    }

    #[test]
    fn test_set_syscall_error() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        ));
        let mut arr = Array::new(&mut map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        assert_matches!(
            arr.set(0, inner_map.fd(), 0),
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_update_elem", .. }))
        );
    }

    #[test]
    fn test_set_ok() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        ));
        let mut arr = Array::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_UPDATE_ELEM,
                ..
            } => Ok(0),
            _ => sys_error(EFAULT),
        });

        assert!(arr.set(0, inner_map.fd(), 0).is_ok());
    }

    #[test]
    fn test_set_out_of_bounds() {
        let mut map = new_map(new_obj_map());
        let inner_map = new_map(test_utils::new_obj_map::<u32>(
            aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY,
        ));
        let mut arr = Array::new(&mut map).unwrap();

        assert_matches!(arr.set(1024, inner_map.fd(), 0), Err(MapError::OutOfBounds { .. }));
    }

    #[test]
    fn test_get_syscall_error() {
        let map = new_map(new_obj_map());
        let arr = Array::new(&map).unwrap();

        override_syscall(|_| sys_error(EFAULT));

        let result = arr.get::<u32>(&0, 0);
        assert!(matches!(
            result,
            Err(MapError::SyscallError(SyscallError { call: "bpf_map_lookup_elem", .. }))
        ));
    }

    #[test]
    fn test_get_not_found() {
        let map = new_map(new_obj_map());
        let arr = Array::new(&map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_LOOKUP_ELEM,
                ..
            } => sys_error(ENOENT),
            _ => sys_error(EFAULT),
        });

        assert!(matches!(arr.get::<u32>(&0, 0), Err(MapError::KeyNotFound)));
    }

    #[test]
    fn test_get_out_of_bounds() {
        let map = new_map(new_obj_map());
        let arr = Array::new(&map).unwrap();

        assert!(matches!(arr.get::<u32>(&1024, 0), Err(MapError::OutOfBounds { .. })));
    }
}
