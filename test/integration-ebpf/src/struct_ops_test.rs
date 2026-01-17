#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{macros::struct_ops, programs::StructOpsContext};
#[cfg(not(test))]
extern crate ebpf_panic;

// A simple struct_ops callback that does nothing but return 0.
// This is used to test that struct_ops section parsing works.
#[struct_ops]
pub(crate) fn struct_ops_test_callback(_ctx: StructOpsContext) -> i32 {
    0
}
