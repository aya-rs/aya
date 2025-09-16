#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::path,
    cty::c_long,
    helpers::bpf_d_path,
    macros::{fentry, map},
    maps::Array,
    memcpy,
    programs::FEntryContext,
};
use integration_common::bpf_d_path::{PATH_BUF_LEN, TestResult};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static RESULT: Array<TestResult> = Array::with_max_entries(1, 0);

#[fentry]
pub fn test_vfs_open(ctx: FEntryContext) -> u32 {
    match try_vfs_open(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_vfs_open(ctx: FEntryContext) -> Result<(), c_long> {
    let dest = &mut [0u8; PATH_BUF_LEN];
    let pathptr: *const path = unsafe { ctx.arg(0) };
    let data = unsafe { bpf_d_path(pathptr, dest)? };

    let mut result = TestResult {
        buf: [0u8; PATH_BUF_LEN],
        len: 0,
    };

    unsafe {
        memcpy(
            result.buf.as_mut_ptr(),
            data.as_ptr() as *mut u8,
            data.len(),
        )
    };

    result.len = dest.len();

    RESULT.set(0, &result, 0)?;

    Ok(())
}
