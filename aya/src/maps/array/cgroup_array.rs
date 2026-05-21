//! An array of cgroups.

use std::{
    borrow::{Borrow, BorrowMut},
    os::fd::{AsRawFd, RawFd},
};

use crate::maps::{MapData, MapError, check_bounds, check_kv_size, hash_map};

/// An array of cgroups.
///
/// eBPF programs can test whether a packet or the current task belongs to a
/// cgroup by calling `bpf_skb_under_cgroup` or `bpf_current_task_under_cgroup`
/// against this map. You populate it from userspace with the file descriptors
/// of cgroup directories.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.8.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// # let cgroup_fd = 1;
/// use aya::maps::CgroupArray;
///
/// let mut array = CgroupArray::try_from(bpf.map_mut("CGROUPS").unwrap())?;
/// // cgroup_fd is the RawFd of an open cgroup directory.
/// array.set(0, cgroup_fd, 0);
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_CGROUP_ARRAY")]
pub struct CgroupArray<T> {
    pub(crate) inner: T,
}

impl<T: Borrow<MapData>> CgroupArray<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<u32, RawFd>(data)?;

        Ok(Self { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.borrow().obj.max_entries()
    }
}

impl<T: BorrowMut<MapData>> CgroupArray<T> {
    /// Stores a cgroup file descriptor at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds,
    /// [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, cgroup_fd: impl AsRawFd, flags: u64) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        hash_map::insert(data, &index, &cgroup_fd.as_raw_fd(), flags)
    }

    /// Un-sets the cgroup at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds,
    /// [`MapError::SyscallError`] if `bpf_map_delete_elem` fails.
    pub fn unset(&mut self, index: u32) -> Result<(), MapError> {
        let data = self.inner.borrow_mut();
        check_bounds(data, index)?;
        hash_map::remove(data, &index)
    }
}
