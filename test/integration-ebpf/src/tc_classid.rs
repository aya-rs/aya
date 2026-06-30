#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};
use integration_common::tc_classid::EXPECTED_CLASSID;
#[cfg(not(test))]
extern crate ebpf_panic;

#[classifier]
fn set_classid(ctx: TcContext) -> i32 {
    ctx.set_tc_classid(EXPECTED_CLASSID);
    TC_ACT_OK
}
