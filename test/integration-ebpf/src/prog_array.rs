#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    cty::c_long,
    macros::{map, uprobe},
    maps::{Array as LegacyArray, ProgramArray as LegacyProgramArray},
    programs::ProbeContext,
};
use integration_common::prog_array::{FAILURE_SENTINEL, RESULT_INDEX};

// The kernel's `bpf_tail_call` helper never populates `R0` on failure, so
// `tail_call` must report failure without inspecting the helper return
// value. An unpopulated slot guarantees the helper falls through.
#[map]
static ARRAY_LEGACY: LegacyProgramArray = LegacyProgramArray::with_max_entries(1, 0);

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(1, 0);

#[uprobe]
fn tail_call_empty_legacy(ctx: ProbeContext) -> Result<(), c_long> {
    if unsafe { ARRAY_LEGACY.tail_call(&ctx, 0) }.is_err() {
        let ptr = RESULT_LEGACY.get_ptr_mut(RESULT_INDEX).ok_or(-1)?;
        unsafe {
            *ptr = FAILURE_SENTINEL;
        }
    }
    Ok(())
}
