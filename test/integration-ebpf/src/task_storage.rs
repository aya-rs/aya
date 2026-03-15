#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    btf_maps::TaskStorage,
    helpers::bpf_get_current_task_btf,
    macros::{btf_map, kprobe},
    programs::ProbeContext,
};

#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static TASK_STORAGE: TaskStorage<u64> = TaskStorage::new();

#[kprobe]
fn task_storage_test(_ctx: ProbeContext) -> i64 {
    let task = unsafe { bpf_get_current_task_btf() };

    let mut initial_val: u64 = 42;
    let ptr = unsafe { TASK_STORAGE.get_or_insert_ptr_mut(Some(task), Some(&mut initial_val)) };
    if ptr.is_null() {
        return 0;
    }

    let val = unsafe { *ptr };
    if val != 42 {
        return 0;
    }

    unsafe {
        *ptr = 1337;
    }
    let ptr = unsafe { TASK_STORAGE.get_ptr_mut(Some(task)) };
    if ptr.is_null() {
        return 0;
    }

    let val = unsafe { *ptr };
    if val != 1337 {
        return 0;
    }

    let ret = unsafe {
        TASK_STORAGE.delete(None /* uses current task */)
    };
    if ret.is_err() {
        return 0;
    }

    let ptr = unsafe { TASK_STORAGE.get_ptr_mut(Some(task)) };
    if !ptr.is_null() {
        return 0;
    }

    0
}
