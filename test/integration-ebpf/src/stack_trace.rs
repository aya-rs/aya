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
use integration_common::stack_trace::{NUM_SLOTS, RESULT_RAN, RESULT_STACKID};

#[btf_map]
static STACKS: BtfStackTrace<1> = BtfStackTrace::new();

#[btf_map]
static RESULT: BtfArray<u32, { NUM_SLOTS as usize }, 0> = BtfArray::new();

#[map]
static STACKS_LEGACY: LegacyStackTrace = LegacyStackTrace::with_max_entries(1, 0);

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(NUM_SLOTS, 0);

macro_rules! define_stack_trace_test {
    ($map:ident, $result:ident, $probe:ident $(,)?) => {
        #[uprobe]
        fn $probe(ctx: ProbeContext) -> Result<(), c_long> {
            let id =
                unsafe { $map.get_stackid::<ProbeContext>(&ctx, u64::from(BPF_F_USER_STACK))? };
            let id_slot = $result.get_ptr_mut(RESULT_STACKID).ok_or(-1)?;
            let ran_slot = $result.get_ptr_mut(RESULT_RAN).ok_or(-1)?;
            unsafe {
                *id_slot = id as u32;
                *ran_slot = 1;
            }
            Ok(())
        }
    };
}

define_stack_trace_test!(STACKS, RESULT, record_stackid);
define_stack_trace_test!(STACKS_LEGACY, RESULT_LEGACY, record_stackid_legacy);
