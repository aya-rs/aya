#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    EbpfContext as _,
    btf_maps::{Array as BtfArray, StackTrace as BtfStackTrace},
    macros::{btf_map, lsm, map},
    maps::{Array as LegacyArray, StackTrace as LegacyStackTrace},
    programs::{LsmContext, tracing::StackIdContext as _},
};
use integration_common::stack_trace::TestResult;

#[btf_map]
static STACKS: BtfStackTrace<1> = BtfStackTrace::new();

#[btf_map]
static RESULT: BtfArray<TestResult, 1, 0> = BtfArray::new();

#[map]
static STACKS_LEGACY: LegacyStackTrace = LegacyStackTrace::with_max_entries(1, 0);

#[map]
static RESULT_LEGACY: LegacyArray<TestResult> = LegacyArray::with_max_entries(1, 0);

// Userspace writes the test's tgid to index 0 so the probe only records stacks
// for this process, avoiding cross-process contamination on busy hosts.
#[map]
static TARGET_TGID: LegacyArray<u32> = LegacyArray::with_max_entries(1, 0);

macro_rules! define_lsm_stack_test {
    ($stacks:ident, $result:ident, $probe:ident $(,)?) => {
        #[lsm(hook = "socket_bind")]
        fn $probe(ctx: LsmContext) -> i32 {
            // `socket_bind(sock, addr, addrlen)` has 3 arguments; the prior LSM
            // program's return value is exposed as a synthetic last argument.
            let retval: i32 = ctx.arg(3);
            let target = TARGET_TGID.get(0).copied().unwrap_or(0);
            if target == 0 || ctx.tgid() != target {
                return retval;
            }
            let Ok(id) = ctx.get_stackid(&$stacks, 0) else {
                return retval;
            };
            let Some(slot) = $result.get_ptr_mut(0) else {
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
    };
}

define_lsm_stack_test!(STACKS, RESULT, record_stackid_lsm);
define_lsm_stack_test!(STACKS_LEGACY, RESULT_LEGACY, record_stackid_lsm_legacy);
