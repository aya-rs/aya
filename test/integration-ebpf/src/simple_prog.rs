// Socket Filter program for testing with an arbitrary program.
// This is mainly used in tests with consideration for old kernels.

#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
aya_ebpf::main_stub!();

use aya_ebpf::{macros::socket_filter, programs::SkBuffContext};
#[cfg(target_arch = "bpf")]
extern crate ebpf_panic;

// Introduced in kernel v3.19.
#[socket_filter]
pub fn simple_prog(_ctx: SkBuffContext) -> i64 {
    0
}
