//! Task storage.
use std::{
    borrow::Borrow,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd},
};

use crate::{
    maps::{check_kv_size, MapData, MapError},
    sys::{bpf_map_lookup_elem, PidFd, SyscallError},
    Pod,
};

/// Task storage is a type of map which uses `task_struct` kernel type as a
/// key. When the task (process) stops, the corresponding entry is
/// automatically removed.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.12.
///
/// # Examples
///
/// ```no_run
/// # let mut ebpf = aya::Ebpf::load(&[])?;
/// use aya::maps::TaskStorage;
///
/// let mut task_storage: TaskStorage<_, u32> = TaskStorage::try_from(ebpf.map_mut("TASK_STORAGE").unwrap())?;
///
/// let pid = 0;
/// let value = task_storage.get(&pid, 0)?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_TASK_STORAGE")]
#[derive(Debug)]
pub struct TaskStorage<T, V> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> TaskStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, V>(data)?;
        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value stored for the given `pid`.
    pub fn get(&self, pid: &u32, flags: u64) -> Result<V, MapError> {
        let pidfd = PidFd::open(*pid, 0).map_err(|(_, io_error)| SyscallError {
            call: "pidfd_open",
            io_error,
        })?;
        let map_fd = self.inner.borrow().fd().as_fd();
        let value =
            bpf_map_lookup_elem(map_fd, &pidfd.as_raw_fd(), flags).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_map_lookup_elem",
                    io_error,
                }
            })?;
        value.ok_or(MapError::KeyNotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use assert_matches::assert_matches;
    use aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE;
    use libc::EFAULT;

    use super::*;
    use crate::{
        maps::{
            test_utils::{self, new_map},
            Map,
        },
        sys::{override_syscall, SysResult, Syscall},
    };

    fn new_obj_map() -> aya_obj::Map {
        test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_TASK_STORAGE)
    }

    fn sys_error(value: i32) -> SysResult<i64> {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_value_size() {
        let map = new_map(new_obj_map());
        let map = Map::TaskStorage(map);
        assert_matches!(
            TaskStorage::<_, u16>::try_from(&map),
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
            TaskStorage::<_, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        assert!(TaskStorage::<_, u32>::new(&map).is_ok());
    }

    #[test]
    fn test_try_from_ok() {
        let map = new_map(new_obj_map());
        let map = Map::TaskStorage(map);
        assert!(TaskStorage::<_, u32>::try_from(&map).is_ok());
    }

    #[test]
    fn test_get_pidfd_syscall_error() {
        let mut map = new_map(new_obj_map());
        let map = TaskStorage::<_, u32>::new(&mut map).unwrap();

        override_syscall(|call| match call {
            Syscall::Ebpf { .. } => Ok(1),
            Syscall::PidfdOpen { .. } => sys_error(EFAULT),
            _ => sys_error(EFAULT),
        });

        assert_matches!(
            map.get(&1, 0), Err(MapError::SyscallError(
                SyscallError {
                    call: "pidfd_open",
                    io_error
                }
            ))
            if io_error.raw_os_error() == Some(EFAULT)
        );
    }
}
