#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::XDP_PASS,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

macro_rules! probe {
    ($name:ident, ($($arg:ident $(= $value:literal)?),*) ) => {
        #[xdp($($arg $(= $value)?),*)]
        const fn $name(_ctx: XdpContext) -> u32 {
            XDP_PASS
        }
    };
}

#[map]
static SEEN: Array<u32> = Array::with_max_entries(1, 0);

#[xdp]
fn xdp_plain(_ctx: XdpContext) -> u32 {
    if let Some(seen) = SEEN.get_ptr_mut(0) {
        unsafe {
            *seen = 1;
        }
    }
    XDP_PASS
}

probe!(xdp_frags, (frags));
probe!(xdp_cpumap, (map = "cpumap"));
probe!(xdp_devmap, (map = "devmap"));
probe!(xdp_frags_cpumap, (frags, map = "cpumap"));
probe!(xdp_frags_devmap, (frags, map = "devmap"));
