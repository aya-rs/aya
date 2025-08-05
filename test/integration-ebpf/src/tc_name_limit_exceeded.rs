#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext};

// A function with a 257-byte-long name (all 'a's) to be used as the name of
// the ebpf program. This name must match the name passed to userspace side
// of the program (i.e. test/integration-test/src/tests/load.rs).
// 256 is the maximum length allowed by the kernel, so this test should fail.
// https://github.com/torvalds/linux/blob/02aee814/net/sched/cls_bpf.c#L28
#[classifier]
pub fn aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(
    _ctx: TcContext,
) -> i32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
