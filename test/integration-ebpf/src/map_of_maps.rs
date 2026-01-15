#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, uprobe},
    maps::{Array, ArrayOfMaps},
    programs::ProbeContext,
};

#[map]
static OUTER: ArrayOfMaps<Array<u32>> = ArrayOfMaps::with_max_entries(10, 0);

#[map]
static INNER: Array<u32> = Array::with_max_entries(10, 0);

#[map]
static INNER_2: Array<u32> = Array::with_max_entries(10, 0);

#[uprobe]
pub fn mim_test_array(_ctx: ProbeContext) -> u32 {
    if let Some(map) = OUTER.get(0) {
        if let Some(idx_0) = map.get_ptr_mut(0) {
            unsafe {
                *idx_0 = 42;
            }
        }
    }
    if let Some(map) = OUTER.get(1) {
        if let Some(idx_0) = map.get_ptr_mut(0) {
            unsafe {
                *idx_0 = 24;
            }
        }
    }

    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
