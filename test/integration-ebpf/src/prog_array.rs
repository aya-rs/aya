#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::{Array, ProgramArray},
    programs::SkBuffContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

/// Result array to track which program was executed.
/// Index 0 = set by main program before tail call
/// Index 1 = set by `tail_0` program
/// Index 2 = set by `tail_1` program
#[map]
static RESULTS: Array<u32> = Array::with_max_entries(4, 0);

/// Program array for tail calls.
#[map]
static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(4, 0);

/// Main entry program that performs a tail call.
#[socket_filter]
fn prog_array_main(ctx: SkBuffContext) -> i64 {
    // Mark that we entered the main program
    if let Some(v) = RESULTS.get_ptr_mut(0) {
        unsafe { *v = 1 }
    }

    // Try to tail call to program at index 0
    unsafe {
        _ = JUMP_TABLE.tail_call(&ctx, 0);
    }

    // If tail call fails, return -1
    -1
}

/// First tail call target.
#[socket_filter]
fn tail_0(ctx: SkBuffContext) -> i64 {
    // Mark that we executed tail_0
    if let Some(v) = RESULTS.get_ptr_mut(1) {
        unsafe { *v = 10 }
    }

    // Chain to tail_1
    unsafe {
        _ = JUMP_TABLE.tail_call(&ctx, 1);
    }

    // If tail call fails, return the result
    0
}

/// Second tail call target.
#[socket_filter]
fn tail_1(_ctx: SkBuffContext) -> i64 {
    // Mark that we executed tail_1
    if let Some(v) = RESULTS.get_ptr_mut(2) {
        unsafe { *v = 20 }
    }

    // End of chain
    0
}
