#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{macros::struct_ops, programs::StructOpsContext};
#[cfg(not(test))]
extern crate ebpf_panic;

/// Test callback implementing a struct_ops member.
/// This tests basic struct_ops section parsing.
#[struct_ops]
pub(crate) fn struct_ops_test_callback(_ctx: StructOpsContext) -> i32 {
    0
}

/// A second callback to test multiple struct_ops programs in one object.
/// The name attribute allows the section name to differ from the function name.
#[struct_ops(name = "another_callback")]
pub(crate) fn struct_ops_second_callback(_ctx: StructOpsContext) -> i32 {
    1
}

/// A sleepable struct_ops callback for testing sleepable section parsing.
#[struct_ops(sleepable)]
pub(crate) fn struct_ops_sleepable_callback(_ctx: StructOpsContext) -> i32 {
    2
}
