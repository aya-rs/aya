#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, kprobe},
    programs::{FEntryContext, ProbeContext},
};

#[kprobe]
pub fn kprobe_vfs_write(ctx: ProbeContext) {
    let _: Option<usize> = ctx.arg(3);
}

#[fentry]
pub fn fentry_vfs_write(ctx: FEntryContext) {
    let _: Option<usize> = unsafe { ctx.arg(3) };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
