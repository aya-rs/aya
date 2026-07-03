#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    EbpfContext as _, Global,
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::syscall_args::{RAN, RESULT_INDEX, TestResult};
#[cfg(not(test))]
extern crate ebpf_panic;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<u32> = Global::new(0);

#[map]
static RESULTS: Array<TestResult> = Array::with_max_entries(1, 0);

// Kprobe on `__arm64_sys_splice` / `__x64_sys_splice` that captures all six
// syscall arguments using `ProbeContext::syscall_arg`. The program filters by
// `TARGET_TGID` (set from userspace) so only the test process's own `splice`
// calls are recorded. See `integration_common::syscall_args` for the shared
// protocol.
#[kprobe]
fn syscall_args_splice(ctx: ProbeContext) -> u32 {
    if ctx.tgid() != TARGET_TGID.load() {
        return 0;
    }

    let fd_in: u64 = ctx.syscall_arg(0).unwrap_or(0);
    let off_in: u64 = ctx.syscall_arg(1).unwrap_or(0);
    let fd_out: u64 = ctx.syscall_arg(2).unwrap_or(0);
    let off_out: u64 = ctx.syscall_arg(3).unwrap_or(0);
    let len: u64 = ctx.syscall_arg(4).unwrap_or(0);
    let flags: u64 = ctx.syscall_arg(5).unwrap_or(0);
    if let Some(result) = RESULTS.get_ptr_mut(RESULT_INDEX) {
        unsafe {
            *result = TestResult {
                ran: RAN,
                fd_in,
                off_in,
                fd_out,
                off_out,
                len,
                flags,
            };
        }
    }
    0
}
