#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
aya_ebpf::prelude!();

use aya_ebpf::{
    macros::{map, raw_tracepoint},
    maps::Array,
    programs::RawTracePointContext,
};
use integration_common::raw_tracepoint::SysEnterEvent;

#[map]
static RESULT: Array<SysEnterEvent> = Array::with_max_entries(1, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let common_type: u16 = unsafe { ctx.arg(0) };
    let common_flags: u8 = unsafe { ctx.arg(1) };

    if let Some(ptr) = RESULT.get_ptr_mut(0) {
        unsafe {
            (*ptr).common_type = common_type;
            (*ptr).common_flags = common_flags;
        }
    }

    0
}
