#![no_std]
#![no_main]

use aya_ebpf::{macros::socket_filter, programs::SkBuffContext};

#[socket_filter]
pub fn read_one(ctx: SkBuffContext) -> i64 {
    // Read 1 byte
    let mut dst = [0; 2];
    let _ = ctx.load_bytes(0, &mut dst);

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
