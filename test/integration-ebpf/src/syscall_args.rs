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
// `const struct pt_regs *` argument. `ProbeContext::syscall_arg` retrieves
// the syscall arguments using the syscall calling convention.
//
// The program is attached to `__arm64_sys_splice` / `__x64_sys_splice` from
// userspace depending on the host architecture. `splice(2)` has six arguments
// — `fd_in, off_in, fd_out, off_out, len, flags` — which exercises all syscall
// argument registers, including the `x86-64`-specific `r10` for argument 4.
// The kprobe records each argument so userspace can verify the values match
// those that were used to invoke the syscall.
//
// Mirrors the kernel selftest in
// https://github.com/torvalds/linux/blob/e5f0a698b34ed76002dc5cff3804a61c80233a7a/tools/testing/selftests/bpf/progs/bpf_syscall_macro.c#L89-L103.
#[kprobe]
fn syscall_args_splice(ctx: ProbeContext) -> u32 {
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
