#![no_std]
#![no_main]

use aya_ebpf::{bindings::tcx_action_base::TCX_NEXT, macros::classifier, programs::TcContext};
#[cfg(not(test))]
use panic_halt as _;

#[classifier]
pub fn tcx_next(_ctx: TcContext) -> i32 {
    TCX_NEXT
}
