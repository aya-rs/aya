use core::ptr;

use aya_ebpf_bindings::bindings::{BPF_F_NO_PREALLOC, BPF_LOCAL_STORAGE_GET_F_CREATE, task_struct};

use crate::{
    btf_maps::btf_map_def,
    helpers::{bpf_get_current_task_btf, bpf_task_storage_delete, bpf_task_storage_get},
};

btf_map_def!(
    /// A BTF-compatible BPF task storage map.
    ///
    /// Task storage maps require `BPF_F_NO_PREALLOC` flag and `max_entries: 0`.
    pub struct TaskStorage<T>,
    map_type: BPF_MAP_TYPE_TASK_STORAGE,
    max_entries: 0,
    map_flags: BPF_F_NO_PREALLOC as usize,
    key_type: i32,
    value_type: T,
);

impl<T> TaskStorage<T> {
    #[inline(always)]
    fn get_ptr(&self, task: Option<*mut task_struct>, value: *mut T, flags: u64) -> *mut T {
        let task = task.unwrap_or_else(|| unsafe { bpf_get_current_task_btf() });
        unsafe { bpf_task_storage_get(self.as_ptr(), task.cast(), value.cast(), flags) }.cast()
    }

    /// Gets a mutable reference to the value associated with `task`.
    ///
    /// If `task` is `None`, the current task is used.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `task`.
    #[inline(always)]
    pub unsafe fn get_ptr_mut(&self, task: Option<*mut task_struct>) -> *mut T {
        self.get_ptr(task, ptr::null_mut(), 0)
    }

    /// Gets a mutable reference to the value associated with `task`.
    ///
    /// If no value is associated with `task`, `value` will be inserted. If
    /// `task` is `None`, the current task is used.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `task`.
    #[inline(always)]
    pub unsafe fn get_or_insert_ptr_mut(
        &self,
        task: Option<*mut task_struct>,
        value: Option<&mut T>,
    ) -> *mut T {
        self.get_ptr(
            task,
            value.map_or(ptr::null_mut(), ptr::from_mut),
            BPF_LOCAL_STORAGE_GET_F_CREATE.into(),
        )
    }

    /// Deletes the value associated with `task`. If `task` is `None`, the
    /// current task is used.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `task`.
    #[inline(always)]
    pub unsafe fn delete(&self, task: Option<*mut task_struct>) -> Result<(), i32> {
        let task = task.unwrap_or_else(|| unsafe { bpf_get_current_task_btf() });
        let ret = unsafe { bpf_task_storage_delete(self.as_ptr(), task.cast()) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}
