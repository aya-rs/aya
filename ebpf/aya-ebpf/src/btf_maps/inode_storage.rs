use core::ptr;

use aya_ebpf_bindings::bindings::{BPF_F_NO_PREALLOC, BPF_LOCAL_STORAGE_GET_F_CREATE, inode};

use crate::{
    btf_maps::btf_map_def,
    helpers::generated::{bpf_inode_storage_delete, bpf_inode_storage_get},
};

btf_map_def!(
    /// A BTF-compatible BPF inode storage map.
    ///
    /// Inode storage maps require the `BPF_F_NO_PREALLOC` flag and `max_entries: 0`.
    pub struct InodeStorage<T>,
    map_type: BPF_MAP_TYPE_INODE_STORAGE,
    max_entries: 0,
    map_flags: BPF_F_NO_PREALLOC as usize,
    key_type: i32,
    value_type: T,
);

impl<T> InodeStorage<T> {
    #[inline(always)]
    fn get_ptr(&self, inode: *mut inode, value: *mut T, flags: u64) -> *mut T {
        unsafe { bpf_inode_storage_get(self.as_ptr(), inode.cast(), value.cast(), flags) }
            .cast::<T>()
    }

    /// Gets a mutable reference to the value associated with `inode`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `inode`.
    #[inline(always)]
    pub unsafe fn get_ptr_mut(&self, inode: *mut inode) -> *mut T {
        self.get_ptr(inode, ptr::null_mut(), 0)
    }

    /// Gets a mutable reference to the value associated with `inode`.
    ///
    /// If no value is associated with `inode`, `value` will be inserted.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `inode`.
    #[inline(always)]
    pub unsafe fn get_or_insert_ptr_mut(&self, inode: *mut inode, value: Option<&mut T>) -> *mut T {
        self.get_ptr(
            inode,
            value.map_or(ptr::null_mut(), ptr::from_mut),
            BPF_LOCAL_STORAGE_GET_F_CREATE.into(),
        )
    }

    /// Deletes the value associated with `inode`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `inode`.
    #[inline(always)]
    pub unsafe fn delete(&self, inode: *mut inode) -> Result<(), i32> {
        let ret = unsafe { bpf_inode_storage_delete(self.as_ptr(), inode.cast()) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}
