//! A cgroup local storage map backed by `BPF_MAP_TYPE_CGRP_STORAGE`.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsRawFd,
};

use crate::{
    Pod,
    maps::{MapData, MapError, check_kv_size, hash_map},
};

/// A cgroup local storage map backed by `BPF_MAP_TYPE_CGRP_STORAGE`.
///
/// This map type stores values that are owned by individual cgroups. The map keys are file
/// descriptors referring to the cgroups and the values can be accessed both from eBPF using
/// `bpf_cgrp_storage_get` and from user space through the methods on this type.
///
/// Unlike the deprecated [`CgroupStorage`](crate::maps::CgroupStorage), this map is available to
/// programs that are not attached to a cgroup.
///
/// The minimum kernel version required to use this feature is 6.2.
#[doc(alias = "BPF_MAP_TYPE_CGRP_STORAGE")]
#[derive(Debug)]
pub struct CgrpStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> CgrpStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<i32, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value associated with `cgroup`.
    pub fn get(&self, cgroup: &impl AsRawFd, flags: u64) -> Result<V, MapError> {
        hash_map::get(self.inner.borrow(), &cgroup.as_raw_fd(), flags)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> CgrpStorage<T, V> {
    /// Creates or updates the value associated with `cgroup`.
    pub fn insert(
        &mut self,
        cgroup: &impl AsRawFd,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            &cgroup.as_raw_fd(),
            value.borrow(),
            flags,
        )
    }

    /// Removes the storage associated with `cgroup`.
    pub fn remove(&mut self, cgroup: &impl AsRawFd) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &cgroup.as_raw_fd())
    }
}
