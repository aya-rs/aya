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

// An unpopulated slot guarantees `bpf_tail_call` falls through to the
// caller; the entry probe records the sentinel from that path.
#[map]
static ARRAY_LEGACY: LegacyProgramArray = LegacyProgramArray::with_max_entries(1, 0);

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(1, 0);

#[uprobe]
fn tail_call_empty_legacy(ctx: ProbeContext) -> Result<(), c_long> {
    // A successful tail call never returns here, so this runs only on
    // failure.
    unsafe {
        ARRAY_LEGACY.tail_call(&ctx, 0);
    }
    let ptr = RESULT_LEGACY.get_ptr_mut(RESULT_INDEX).ok_or(-1)?;
    unsafe {
        *ptr = FAILURE_SENTINEL;
    }
    Ok(())
}
