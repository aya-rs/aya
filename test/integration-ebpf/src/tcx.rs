#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::tcx_action_base::TCX_NEXT,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static SEEN: Array<u32> = Array::with_max_entries(1, 0);

#[classifier]
fn tcx_next(_ctx: TcContext) -> i32 {
    if let Some(seen) = SEEN.get_ptr_mut(0) {
        unsafe {
            *seen = 1;
        }
    }
    TCX_NEXT
}
