#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

//! BTF-compatible map-of-maps test.
//!
//! This test uses the BTF map definitions which should be compatible
//! with libbpf loaders.

use aya_ebpf::{
    btf_maps::{Array, ArrayOfMaps},
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};

#[cfg(not(test))]
extern crate ebpf_panic;

// The inner map definition is parsed from the BTF `values` field at load time.
#[btf_map]
static OUTER: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new();

// Result array to verify values from userspace.
#[btf_map]
static RESULTS: Array<u32, 4> = Array::new();

#[unsafe(no_mangle)]
#[inline(never)]
#[expect(
    clippy::missing_const_for_fn,
    reason = "extern functions cannot be const"
)]
pub extern "C" fn trigger_btf_map_of_maps() {
    core::hint::black_box(());
}

/// Reads a value from an inner array selected via the outer map and stores the result.
#[uprobe]
pub(crate) fn test_btf_array_of_maps(_ctx: ProbeContext) -> u32 {
    if let Some(inner) = OUTER.get(0) {
        if let Some(val) = inner.get(0) {
            if let Some(ptr) = RESULTS.get_ptr_mut(0) {
                unsafe {
                    *ptr = *val;
                }
            }
        }
    }
    // Mark test ran.
    if let Some(ptr) = RESULTS.get_ptr_mut(1) {
        unsafe {
            *ptr = 1;
        }
    }
    0
}
