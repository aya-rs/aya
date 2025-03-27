#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
aya_ebpf::main_stub!();

use core::hint;

use aya_ebpf::{
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

#[map]
static RESULTS: Array<u64> = Array::with_max_entries(3, 0);

#[uprobe]
pub fn test_64_32_call_relocs(_ctx: ProbeContext) {
    // this will link set_result and do a forward call
    set_result(0, hint::black_box(1));

    // set_result is already linked, this will just do the forward call
    set_result(1, hint::black_box(2));

    // this will link set_result_backward after set_result. Then will do a
    // backward call to set_result.
    set_result_backward(2, hint::black_box(3));
}

#[inline(never)]
fn set_result(index: u32, value: u64) {
    unsafe {
        if let Some(v) = RESULTS.get_ptr_mut(index) {
            *v = value;
        }
    }
}

#[inline(never)]
fn set_result_backward(index: u32, value: u64) {
    set_result(index, value);
}

aya_ebpf::panic_handler!();
