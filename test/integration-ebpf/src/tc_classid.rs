#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{EbpfContext as _, bindings::__sk_buff, macros::classifier, programs::TcContext};
use integration_common::tc_classid::EXPECTED_CLASSID;
#[cfg(not(test))]
extern crate ebpf_panic;

#[classifier]
fn set_classid(ctx: TcContext) -> i32 {
    ctx.set_tc_classid(EXPECTED_CLASSID);

    // Read the field back and return it so the test can assert the store
    // happened. Volatile so the compiler emits the BPF load instead of
    // forwarding the store above.
    let skb = ctx.as_ptr().cast::<__sk_buff>();
    let read_back = unsafe { core::ptr::read_volatile(&raw const (*skb).tc_classid) };
    read_back as i32
}
