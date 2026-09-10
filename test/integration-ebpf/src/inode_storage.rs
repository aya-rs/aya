#![no_std]
#![no_main]
#![allow(
    unused_crate_dependencies,
    reason = "ebpf_panic is only required for non-test eBPF builds; importing it unconditionally would register its panic handler during tests and conflict with std"
)]

#[cfg(not(test))]
extern crate ebpf_panic;

// Required for satisfying unused-crate-dependencies lint
#[rustfmt::skip]
use aya_log_ebpf as _;
#[rustfmt::skip]
use integration_ebpf as _;
#[rustfmt::skip]
use network_types as _;

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
    if TARGET_TGID.get(0).copied() != Some(ctx.tgid()) {
        return retval;
    }
    let inode: *mut inode = ctx.arg(0);
    let storage = INODE_STORAGE.get_or_insert_ptr_mut(inode, None);
    if !storage.is_null() {
        unsafe { *storage = SENTINEL }
    }
    retval
}
