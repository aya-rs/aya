#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{bindings::tcx_action_base::TCX_NEXT, macros::classifier, programs::TcContext};
#[cfg(not(test))]
extern crate ebpf_panic;

#[classifier]
const fn tcx_next(_ctx: TcContext) -> i32 {
    TCX_NEXT
}

#[classifier]
fn tcx_mutability(ctx: TcContext) -> i32 {
    // Prove that we can call mutating helpers on an immutable context.
    // If the Verifier rejects this, or if a future regression reverts
    // `&self` to `&mut self`, this test will fail to compile or load.
    ctx.set_mark(42);

    let val: u32 = 123;
    let _ = ctx.store(0, &val, 0);

    TCX_NEXT
}
