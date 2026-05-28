#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    bindings::cgroup,
    btf_maps::CgrpStorage,
    macros::{btf_map, btf_tracepoint},
    programs::BtfTracePointContext,
};
use integration_common::local_storage::SENTINEL;

#[btf_map]
static CGRP_STORAGE: CgrpStorage<u64> = CgrpStorage::new();

#[btf_tracepoint(function = "cgroup_mkdir")]
fn cgrp_storage_test(ctx: BtfTracePointContext) -> i32 {
    // `cgroup_mkdir(struct cgroup *cgrp, const char *path)` exposes the new
    // cgroup as the first argument.
    let cgrp: *mut cgroup = ctx.arg(0);
    let storage = unsafe { CGRP_STORAGE.get_or_insert_ptr_mut(cgrp, None) };
    if !storage.is_null() {
        unsafe { *storage = SENTINEL }
    }
    0
}
