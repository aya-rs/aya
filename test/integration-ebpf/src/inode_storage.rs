#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    EbpfContext as _,
    bindings::inode,
    btf_maps::InodeStorage,
    macros::{btf_map, lsm, map},
    maps::Array,
    programs::LsmContext,
};
use integration_common::local_storage::SENTINEL;

#[btf_map]
static INODE_STORAGE: InodeStorage<u64> = InodeStorage::new();

// Userspace writes the test's tgid to index 0 so the probe only records storage
// for this process, avoiding contamination from unrelated inode accesses.
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[lsm(hook = "inode_permission")]
fn inode_storage_test(ctx: LsmContext) -> i32 {
    // `inode_permission(inode, mask)` has 2 arguments; the prior LSM program's
    // return value is exposed as a synthetic last argument.
    let retval: i32 = ctx.arg(2);
    let target = TARGET_TGID.get(0).copied().unwrap_or(0);
    if target == 0 || ctx.tgid() != target {
        return retval;
    }
    let inode: *mut inode = ctx.arg(0);
    let storage = unsafe { INODE_STORAGE.get_or_insert_ptr_mut(inode, None) };
    if !storage.is_null() {
        unsafe { *storage = SENTINEL }
    }
    retval
}
