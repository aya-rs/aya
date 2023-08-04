#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};

macro_rules! probe {
    ($name:ident, ($($arg:ident $(= $value:literal)?),*) ) => {
        #[xdp($($arg $(= $value)?),*)]
        pub fn $name(_ctx: XdpContext) -> u32 {
            XDP_PASS
        }
    };
}

probe!(xdp_plain, ());
probe!(xdp_frags, (frags));
probe!(xdp_cpumap, (map = "cpumap"));
probe!(xdp_devmap, (map = "devmap"));
probe!(xdp_frags_cpumap, (frags, map = "cpumap"));
probe!(xdp_frags_devmap, (frags, map = "devmap"));

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
