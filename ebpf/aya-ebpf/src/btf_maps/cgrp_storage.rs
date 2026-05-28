use core::ptr;

use aya_ebpf_bindings::bindings::{BPF_F_NO_PREALLOC, BPF_LOCAL_STORAGE_GET_F_CREATE, cgroup};

use crate::{
    btf_maps::btf_map_def,
    helpers::generated::{bpf_cgrp_storage_delete, bpf_cgrp_storage_get},
};

btf_map_def!(
    /// A BTF-compatible BPF cgroup storage map.
    ///
    /// Cgroup storage maps require the `BPF_F_NO_PREALLOC` flag and `max_entries: 0`.
    pub struct CgrpStorage<T>,
    map_type: BPF_MAP_TYPE_CGRP_STORAGE,
    max_entries: 0,
    map_flags: BPF_F_NO_PREALLOC as usize,
    key_type: i32,
    value_type: T,
);

impl<T> CgrpStorage<T> {
    #[inline(always)]
    fn get_ptr(&self, cgroup: *mut cgroup, value: *mut T, flags: u64) -> *mut T {
        unsafe { bpf_cgrp_storage_get(self.as_ptr(), cgroup, value.cast(), flags) }.cast::<T>()
    }

    /// Gets a mutable reference to the value associated with `cgroup`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `cgroup`.
    #[inline(always)]
    pub unsafe fn get_ptr_mut(&self, cgroup: *mut cgroup) -> *mut T {
        self.get_ptr(cgroup, ptr::null_mut(), 0)
    }

    /// Gets a mutable reference to the value associated with `cgroup`.
    ///
    /// If no value is associated with `cgroup`, `value` will be inserted.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `cgroup`.
    #[inline(always)]
    pub unsafe fn get_or_insert_ptr_mut(
        &self,
        cgroup: *mut cgroup,
        value: Option<&mut T>,
    ) -> *mut T {
        self.get_ptr(
            cgroup,
            value.map_or(ptr::null_mut(), ptr::from_mut),
            BPF_LOCAL_STORAGE_GET_F_CREATE.into(),
        )
    }

    /// Deletes the value associated with `cgroup`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `cgroup`.
    #[inline(always)]
    pub unsafe fn delete(&self, cgroup: *mut cgroup) -> Result<(), i32> {
        let ret = unsafe { bpf_cgrp_storage_delete(self.as_ptr(), cgroup) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}
