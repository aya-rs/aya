#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    Global,
    bindings::path,
    helpers::{bpf_d_path, bpf_get_current_pid_tgid},
    macros::{fentry, map},
    maps::Array,
    programs::FEntryContext,
};
use integration_common::bpf_d_path::TestResult;

#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static RESULT: Array<TestResult> = Array::with_max_entries(1, 0);

#[unsafe(no_mangle)]
static TARGET_TID: Global<u32> = Global::new(0);

#[fentry]
fn test_vfs_open(ctx: FEntryContext) -> u32 {
    let target_tid = TARGET_TID.load();
    if target_tid != 0 {
        let tid = bpf_get_current_pid_tgid() as u32;
        if tid != target_tid {
            return 0;
        }
    }

    let pathptr: *const path = ctx.arg(0);
    if pathptr.is_null() {
        return 0;
    }

    let Some(result) = RESULT.get_ptr_mut(0) else {
        return 0;
    };
    let result = unsafe { &mut *result };
    result.seen = result.seen.saturating_add(1);

    match unsafe { bpf_d_path(pathptr, &mut result.buf) } {
        Ok(data) => {
            result.len = data.len();
            result.status = 0;
        }
        Err(err) => {
            result.len = 0;
            result.status = err;
        }
    }

    0
}
