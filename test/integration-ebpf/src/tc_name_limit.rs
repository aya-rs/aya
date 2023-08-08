#![no_std]
#![no_main]

use aya_bpf::{macros::classifier, programs::TcContext};

// This macro generates a function with arbitrary name
macro_rules! generate_ebpf_function {
    ($fn_name:ident) => {
        #[classifier]
        pub fn $fn_name(_ctx: TcContext) -> i32 {
            0
        }
    };
}

/*
Generating a function with a 256-byte-long name (all 'a's) to be used as
the ebpf program. This name must match the name passed to userspace side.
256 is the maximum length allowed by the kernel:
https://github.com/torvalds/linux/blob/02aee814/net/sched/cls_bpf.c#L28
*/
generate_ebpf_function!(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
