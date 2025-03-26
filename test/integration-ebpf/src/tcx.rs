#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
aya_ebpf::main_stub!();

use aya_ebpf::{bindings::tcx_action_base::TCX_NEXT, macros::classifier, programs::TcContext};

#[classifier]
pub fn tcx_next(_ctx: TcContext) -> i32 {
    TCX_NEXT
}
