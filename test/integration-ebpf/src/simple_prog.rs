#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{macros::socket_filter, programs::SkBuffContext};
#[cfg(not(test))]
extern crate ebpf_panic;

// Introduced in kernel v3.19.
#[socket_filter]
fn simple_prog(_ctx: SkBuffContext) -> i64 {
    0
}
