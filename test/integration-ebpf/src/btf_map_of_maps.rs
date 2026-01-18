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

// Inner map template - must be declared before outer map
#[btf_map]
static INNER: Array<u32, 10> = Array::new();

// Outer map with BTF-compatible inner map reference
#[btf_map]
static OUTER: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new(&INNER);

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_btf_map_of_maps() {
    core::hint::black_box(());
}

/// Test BTF ArrayOfMaps: read value from inner array via outer map
#[uprobe]
pub(crate) fn test_btf_array_of_maps(_ctx: ProbeContext) -> u32 {
    if let Some(inner) = OUTER.get(0) {
        if let Some(val) = inner.get(0) {
            return *val;
        }
    }
    0
}
