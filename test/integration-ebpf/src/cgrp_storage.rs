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
    let storage = CGRP_STORAGE.get_or_insert_ptr_mut(cgrp, None);
    if !storage.is_null() {
        unsafe { *storage = SENTINEL }
    }
    0
}
