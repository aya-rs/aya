#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, raw_tracepoint},
    maps::Array,
    programs::RawTracePointContext,
};

#[map]
static RESULT: Array<SysEnterEvent> = Array::with_max_entries(1, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysEnterEvent {
    pub common_type: u16,
    pub common_flags: u8,
    _padding: u8,
}

impl SysEnterEvent {
    pub fn new(common_type: u16, common_flags: u8) -> Self {
        Self {
            common_type,
            common_flags,
            _padding: 0,
        }
    }
}

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
