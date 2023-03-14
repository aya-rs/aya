#![no_std]
#![no_main]

use aya_bpf::{
    cty::{c_long, c_longlong},
    macros::{fentry, kprobe},
    programs::{FEntryContext, ProbeContext},
};

#[kprobe]
pub fn kprobe_vfs_write(ctx: ProbeContext) {
    let _ = try_kprobe_vfs_write(ctx);
}

fn try_kprobe_vfs_write(ctx: ProbeContext) -> Result<(), c_long> {
    let _pos: *const c_longlong = ctx.arg(3).ok_or(1)?;
    Ok(())
}

#[fentry]
pub fn fentry_vfs_write(ctx: FEntryContext) {
    let _ = try_fentry_vfs_write(ctx);
}

fn try_fentry_vfs_write(ctx: FEntryContext) -> Result<(), c_long> {
    let _pos: *const c_longlong = unsafe { ctx.arg(3).ok_or(1)? };
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
