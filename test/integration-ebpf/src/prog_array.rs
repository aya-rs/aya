#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array as BtfArray, ProgramArray as BtfProgramArray},
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array as LegacyArray, ProgramArray as LegacyProgramArray},
    programs::ProbeContext,
};
use integration_common::prog_array::{
    FAILURE_SENTINEL, RESULT_INDEX, SUCCESS_INDEX, SUCCESS_SENTINEL,
};

// The kernel's `bpf_tail_call` helper never populates `R0` on failure, so
// `tail_call` must report failure without inspecting the helper return
// value. An unpopulated slot guarantees the helper falls through.
#[btf_map]
static ARRAY: BtfProgramArray<1, 0> = BtfProgramArray::new();

#[btf_map]
static RESULT: BtfArray<u32, 2, 0> = BtfArray::new();

#[map]
static ARRAY_LEGACY: LegacyProgramArray = LegacyProgramArray::with_max_entries(1, 0);

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(2, 0);

macro_rules! define_prog_array_tail_call_test {
    ($array_map:ident, $result_map:ident, $entry_probe:ident, $target_probe:ident $(,)?) => {
        #[uprobe]
        fn $entry_probe(ctx: ProbeContext) -> Result<(), c_long> {
            if unsafe { $array_map.tail_call(&ctx, 0) }.is_err() {
                let ptr = $result_map.get_ptr_mut(RESULT_INDEX).ok_or(-1)?;
                unsafe {
                    *ptr = FAILURE_SENTINEL;
                }
            }
            Ok(())
        }

        #[uprobe]
        fn $target_probe(_ctx: ProbeContext) -> Result<(), c_long> {
            let ptr = $result_map.get_ptr_mut(SUCCESS_INDEX).ok_or(-1)?;
            unsafe {
                *ptr = SUCCESS_SENTINEL;
            }
            Ok(())
        }
    };
}

define_prog_array_tail_call_test!(ARRAY, RESULT, tail_call_empty, tail_call_target);
define_prog_array_tail_call_test!(
    ARRAY_LEGACY,
    RESULT_LEGACY,
    tail_call_empty_legacy,
    tail_call_target_legacy,
);
