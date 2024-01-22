#![no_std]
#![no_main]

use core::cmp::Ordering;

use aya_bpf::{
    cty::c_long,
    helpers::{bpf_probe_read_user_str_bytes, bpf_strncmp},
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

#[repr(C)]
struct TestResult(Ordering);

#[map]
static RESULT: Array<TestResult> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn test_bpf_strncmp(ctx: ProbeContext) -> Result<(), c_long> {
    let str_bytes: *const u8 = ctx.arg(0).ok_or(-1)?;
    let mut buf = [0u8; 16];
    let str_bytes = unsafe { bpf_probe_read_user_str_bytes(str_bytes, &mut buf)? };

    let ptr = RESULT.get_ptr_mut(0).ok_or(-1)?;
    let dst = unsafe { ptr.as_mut() };
    let TestResult(dst_res) = dst.ok_or(-1)?;

    let cmp_res = bpf_strncmp(str_bytes, c"fff");
    *dst_res = cmp_res;

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
