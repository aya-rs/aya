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
static PID: Array<u32> = Array::with_max_entries(1, 0);

#[fentry]
fn test_dentry_open(ctx: FEntryContext) -> u32 {
    match try_dentry_open(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_dentry_open(ctx: FEntryContext) -> Result<(), c_long> {
    let target_pid = PID.get(0).copied().unwrap_or(0);
    if target_pid != 0 {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if pid != target_pid {
            return Ok(());
        }
    }

    let pathptr: *const path = ctx.arg(0);
    if pathptr.is_null() {
        return Ok(());
    }

    if let Some(result) = RESULT.get_ptr_mut(0) {
        let result = unsafe { &mut *result };
        let data = unsafe { bpf_d_path(pathptr, &mut result.buf)? };
        result.len = data.len();
    }

    Ok(())
}
