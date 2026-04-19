#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::path,
    cty::c_long,
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

#[map]
static TID: Array<u32> = Array::with_max_entries(1, 0);

#[fentry]
fn test_vfs_open(ctx: FEntryContext) -> u32 {
    match try_vfs_open(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_vfs_open(ctx: FEntryContext) -> Result<(), c_long> {
    let target_tid = TID.get(0).copied().unwrap_or(0);
    if target_tid != 0 {
        let tid = bpf_get_current_pid_tgid() as u32;
        if tid != target_tid {
            return Ok(());
        }
    }

    let pathptr: *const path = ctx.arg(0);
    if pathptr.is_null() {
        return Ok(());
    }

    if let Some(result) = RESULT.get_ptr_mut(0) {
        let result = unsafe { &mut *result };
        result.seen = result.seen.saturating_add(1);

        match unsafe { bpf_d_path(pathptr, &mut result.buf) } {
            Ok(data) => {
                result.len = data.len();
                result.status = 0;
            }
            Err(err) => {
                result.len = 0;
                result.status = err as i64;
            }
        }
    }

    Ok(())
}
