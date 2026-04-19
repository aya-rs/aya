#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{macros::socket_filter, programs::SkBuffContext};

#[cfg(not(test))]
extern crate ebpf_panic;

#[socket_filter]
fn read_one(ctx: SkBuffContext) -> i64 {
    // Read 1 byte
    let mut dst = [0; 2];
    let _result: Result<_, _> = ctx.load_bytes(0, &mut dst);

    0
}
