#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, raw_tracepoint},
    maps::Array,
    programs::RawTracePointContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;
use integration_common::raw_tracepoint::SysEnterEvent;

#[map]
static RESULT: Array<SysEnterEvent> = Array::with_max_entries(1, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let common_type: u16 = ctx.arg(0);
    let common_flags: u8 = ctx.arg(1);

    if let Some(ptr) = RESULT.get_ptr_mut(0) {
        unsafe {
            (*ptr).common_type = common_type;
            (*ptr).common_flags = common_flags;
        }
    }

    0
}
