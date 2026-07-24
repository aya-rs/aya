//! An inode local storage map backed by `BPF_MAP_TYPE_INODE_STORAGE`.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsRawFd,
};

use crate::{
    Pod,
    maps::{MapData, MapError, check_kv_size, hash_map},
};

/// An inode local storage map backed by `BPF_MAP_TYPE_INODE_STORAGE`.
///
/// This map type stores values that are owned by individual inodes. The map keys are file
/// descriptors referring to the inodes and the values can be accessed both from eBPF using
/// `bpf_inode_storage_get` and from user space through the methods on this type.
///
/// The minimum kernel version required to use this feature is 5.10.
#[doc(alias = "BPF_MAP_TYPE_INODE_STORAGE")]
#[derive(Debug)]
pub struct InodeStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> InodeStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<i32, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value associated with `inode`.
    pub fn get(&self, inode: &impl AsRawFd, flags: u64) -> Result<V, MapError> {
        hash_map::get(self.inner.borrow(), &inode.as_raw_fd(), flags)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> InodeStorage<T, V> {
    /// Creates or updates the value associated with `inode`.
    pub fn insert(
        &mut self,
        inode: &impl AsRawFd,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            &inode.as_raw_fd(),
            value.borrow(),
            flags,
        )
    }

    /// Removes the storage associated with `inode`.
    pub fn remove(&mut self, inode: &impl AsRawFd) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &inode.as_raw_fd())
    }
}
