#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _, Global,
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
use integration_common::syscall_args::SpliceArgs;
#[cfg(not(test))]
extern crate ebpf_panic;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<u32> = Global::new(0);

#[map]
static RESULTS: Array<SpliceArgs> = Array::with_max_entries(1, 0);

// Kprobe on `__arm64_sys_splice` / `__x64_sys_splice` that captures all six
// syscall arguments using `ProbeContext::syscall_arg`. The program filters by
// `TARGET_TGID` (set from userspace) so only the test process's own `splice`
// calls are recorded.
//
// `ProbeContext::syscall_arg` is only provided on AArch64 and x86-64; on other
// architectures the probe is a no-op and the userspace test skips.
#[kprobe]
fn syscall_args_splice(ctx: ProbeContext) -> u32 {
    if ctx.tgid() != TARGET_TGID.load() {
        return 0;
    }

    cfg_select! {
        any(bpf_target_arch = "aarch64", bpf_target_arch = "x86_64") => {
            if let Some(result) = RESULTS.get_ptr_mut(0) {
                unsafe {
                    *result = [
                        ctx.syscall_arg(0).unwrap_or(0),
                        ctx.syscall_arg(1).unwrap_or(0),
                        ctx.syscall_arg(2).unwrap_or(0),
                        ctx.syscall_arg(3).unwrap_or(0),
                        ctx.syscall_arg(4).unwrap_or(0),
                        ctx.syscall_arg(5).unwrap_or(0),
                    ];
                }
            }
        }
        _ => {}
    }
    0
}
