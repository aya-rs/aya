//! Cgroup storage maps.
#![expect(
    deprecated,
    reason = "this module implements the deprecated cgroup storage map types"
)]

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use aya_obj::generated::bpf_cgroup_storage_key;

use crate::{
    Pod,
    maps::{MapData, MapError, PerCpuValues, check_kv_size, hash_map},
    sys::{SyscallError, bpf_map_lookup_elem_per_cpu, bpf_map_update_elem_per_cpu},
};

unsafe impl Pod for bpf_cgroup_storage_key {}

/// A key into a [`CgroupStorage`] or [`PerCpuCgroupStorage`] map.
///
/// The kernel keys cgroup storage entries by the cgroup inode id and the attach
/// type of the program that created them. Only this isolated key layout is
/// supported; the shared `u64` cgroup-inode-id key added in Linux 5.9 is not.
#[derive(Clone, Copy, Debug)]
pub struct CgroupStorageKey {
    cgroup_inode_id: u64,
    attach_type: u32,
}

impl CgroupStorageKey {
    /// Creates a key from a cgroup inode id and a program attach type.
    pub const fn new(cgroup_inode_id: u64, attach_type: u32) -> Self {
        Self {
            cgroup_inode_id,
            attach_type,
        }
    }

    const fn to_kernel(self) -> bpf_cgroup_storage_key {
        let Self {
            cgroup_inode_id,
            attach_type,
        } = self;
        bpf_cgroup_storage_key {
            cgroup_inode_id,
            attach_type,
        }
    }
}

/// A cgroup storage map backed by `BPF_MAP_TYPE_CGROUP_STORAGE`.
///
/// This map stores a single value per cgroup that an attached program runs in.
/// eBPF programs access it through the `bpf_get_local_storage` helper; from user
/// space the entry is read and updated with the methods on this type, keyed by
/// [`CgroupStorageKey`]. The kernel creates entries when a program is attached to
/// a cgroup, so user space can neither create nor delete them.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.19.
#[deprecated = "use the `BPF_MAP_TYPE_CGRP_STORAGE` map type, available since Linux 6.2"]
#[doc(alias = "BPF_MAP_TYPE_CGROUP_STORAGE")]
#[derive(Debug)]
pub struct CgroupStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> CgroupStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<bpf_cgroup_storage_key, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value stored for `key`.
    pub fn get(&self, key: CgroupStorageKey, flags: u64) -> Result<V, MapError> {
        hash_map::get(self.inner.borrow(), &key.to_kernel(), flags)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> CgroupStorage<T, V> {
    /// Updates the value stored for `key`.
    ///
    /// Only existing entries can be updated; the kernel returns `ENOENT` for a
    /// cgroup that has no attached program using this map.
    pub fn insert(
        &mut self,
        key: CgroupStorageKey,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            &key.to_kernel(),
            value.borrow(),
            flags,
        )
    }
}

/// A per-CPU cgroup storage map backed by `BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE`.
///
/// Like [`CgroupStorage`] but each CPU holds a separate value for a given cgroup,
/// so [`get`](Self::get) returns one value per CPU.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
#[deprecated = "use the `BPF_MAP_TYPE_CGRP_STORAGE` map type, available since Linux 6.2"]
#[doc(alias = "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE")]
#[derive(Debug)]
pub struct PerCpuCgroupStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> PerCpuCgroupStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<bpf_cgroup_storage_key, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns a slice of values - one for each CPU - stored for `key`.
    pub fn get(&self, key: CgroupStorageKey, flags: u64) -> Result<PerCpuValues<V>, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let values =
            bpf_map_lookup_elem_per_cpu(fd, &key.to_kernel(), flags).map_err(|io_error| {
                SyscallError {
                    call: "bpf_map_lookup_elem",
                    io_error,
                }
            })?;
        values.ok_or(MapError::KeyNotFound)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> PerCpuCgroupStorage<T, V> {
    /// Updates the per-CPU values stored for `key`.
    ///
    /// Only existing entries can be updated; the kernel returns `ENOENT` for a
    /// cgroup that has no attached program using this map.
    pub fn insert(
        &mut self,
        key: CgroupStorageKey,
        values: PerCpuValues<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        let fd = self.inner.borrow_mut().fd().as_fd();
        bpf_map_update_elem_per_cpu(fd, &key.to_kernel(), &values, flags)
            .map_err(|io_error| SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            })
            .map_err(Into::into)
    }
}
