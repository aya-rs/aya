// this file aims at reproducing the bug reported here: https://github.com/aya-rs/aya/issues/808
#![no_std]
#![no_main]

use aya_bpf::{helpers::bpf_get_prandom_u32, macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::error;

#[repr(C)]
enum Error {
    Foo,
    Bar,
}

impl Error {
    const fn into_str(self) -> &'static str {
        match self {
            Self::Foo => "foo",
            Self::Bar => "bar",
        }
    }
}

#[kprobe]
pub fn log_str_random(ctx: ProbeContext) -> u32 {
    match try_log_str_random(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_log_str_random(ctx: ProbeContext) -> Result<u32, u32> {
    let err = {
        if unsafe { bpf_get_prandom_u32() } % 2 == 0 {
            Error::Bar
        } else {
            Error::Foo
        }
    };
    error!(&ctx, "{}", err.into_str());
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
