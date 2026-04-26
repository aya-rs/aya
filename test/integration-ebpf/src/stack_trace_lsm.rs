#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    EbpfContext as _,
    macros::{lsm, map},
    maps::{Array, StackTrace},
    programs::{LsmContext, tracing::StackIdContext as _},
};
use integration_common::stack_trace::TestResult;

#[map]
static STACKS: StackTrace = StackTrace::with_max_entries(1, 0);

#[map]
static RESULT: Array<TestResult> = Array::with_max_entries(1, 0);

// Userspace writes the test's tgid to index 0 so the probe only records stacks
// for this process, avoiding cross-process contamination on busy hosts.
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[lsm(hook = "socket_bind")]
fn record_stackid_lsm(ctx: LsmContext) -> i32 {
    // `socket_bind(sock, addr, addrlen)` has 3 arguments; the prior LSM
    // program's return value is exposed as a synthetic last argument.
    let retval: i32 = ctx.arg(3);
    let target = TARGET_TGID.get(0).copied().unwrap_or(0);
    if target == 0 || ctx.tgid() != target {
        return retval;
    }
    let Ok(id) = ctx.get_stackid(&STACKS, 0) else {
        return retval;
    };
    let Some(slot) = RESULT.get_ptr_mut(0) else {
        return retval;
    };
    unsafe {
        *slot = TestResult {
            stack_id: id as u32,
            ran: true,
        };
    }
    retval
}
