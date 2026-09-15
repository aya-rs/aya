//! eBPF program using only `btf_maps` (no legacy maps).
//!
//! This program tests BTF map loading with Aya and libbpf.

#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::Array,
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};

#[btf_map]
static BTF_ARRAY: Array<[[u32; 3]; 2], 16> = Array::new();

#[uprobe]
fn btf_maps_plain(_ctx: ProbeContext) -> u32 {
    if let Some(value) = BTF_ARRAY.get(0) {
        let [_, row] = value;
        let [_, _, value] = row;
        *value
    } else {
        0
    }
}
