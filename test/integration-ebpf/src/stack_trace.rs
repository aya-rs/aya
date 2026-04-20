#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    btf_maps::{Array as BtfArray, StackTrace as BtfStackTrace},
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array as LegacyArray, StackTrace as LegacyStackTrace},
    programs::ProbeContext,
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

macro_rules! define_stack_trace_test {
    ($map:ident, $result:ident, $probe:ident $(,)?) => {
        #[uprobe]
        fn $probe(ctx: ProbeContext) -> Result<(), c_long> {
            let id =
                unsafe { $map.get_stackid::<ProbeContext>(&ctx, u64::from(BPF_F_USER_STACK))? };
            let slot = $result.get_ptr_mut(0).ok_or(-1)?;
            unsafe {
                *slot = TestResult {
                    stack_id: id as u32,
                    ran: 1,
                };
            }
            Ok(())
        }
    };
}

define_stack_trace_test!(STACKS, RESULT, record_stackid);
define_stack_trace_test!(STACKS_LEGACY, RESULT_LEGACY, record_stackid_legacy);
