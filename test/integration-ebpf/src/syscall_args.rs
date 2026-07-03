#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::syscall_args::{RAN, RESULT_INDEX, TestResult};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static RESULTS: Array<TestResult> = Array::with_max_entries(1, 0);

// Used in tests on platforms where the probed function is a syscall wrapper
// (CONFIG_ARCH_HAS_SYSCALL_WRAPPER), which takes a single
// `const struct pt_regs *` argument. [`ProbeContext::syscall_arg`] retrieves
// the syscall arguments using the syscall calling convention.
//
// The program is attached to `__arm64_sys_kill` / `__x64_sys_kill` from
// userspace depending on the host architecture. The kprobe records the `pid`
// and `sig` arguments passed to the `kill(2)` syscall so that userspace can
// verify the values match those that were used to invoke it.
#[kprobe]
fn syscall_args_kill(ctx: ProbeContext) -> u32 {
    let pid: i32 = ctx.syscall_arg(0).unwrap_or(-1);
    let sig: i32 = ctx.syscall_arg(1).unwrap_or(-1);
    if let Some(result) = RESULTS.get_ptr_mut(RESULT_INDEX) {
        unsafe {
            *result = TestResult { ran: RAN, pid, sig };
        }
    }
    0
}
