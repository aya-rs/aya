//! eBPF program using only btf_maps (no legacy maps).
//!
//! This program is used to test that libbpf can load BTF maps
//! produced by aya-ebpf's btf_maps module.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::Array,
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};

#[btf_map]
static BTF_ARRAY: Array<u64, 16> = Array::new();

#[uprobe]
pub fn btf_maps_plain(_ctx: ProbeContext) -> u32 {
    if let Some(value) = BTF_ARRAY.get(0) {
        *value as u32
    } else {
        0
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
