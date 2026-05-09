#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

//! BTF-compatible map-of-maps tests.
//!
//! Uses BTF map definitions compatible with both aya and libbpf loaders.

use aya_ebpf::{
    btf_maps::{Array, ArrayOfMaps, HashOfMaps},
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};
use integration_common::btf_map_of_maps::TestResult;

#[cfg(not(test))]
extern crate ebpf_panic;

#[btf_map]
static ARRAY_OF_MAPS: ArrayOfMaps<Array<u32, 10>, 4> = ArrayOfMaps::new();

#[btf_map]
static HASH_OF_MAPS: HashOfMaps<u32, Array<u32, 10>, 4> = HashOfMaps::new();

#[btf_map]
static RESULTS: Array<TestResult, 4> = Array::new();

#[unsafe(no_mangle)]
#[inline(never)]
pub const extern "C" fn trigger_btf_array_of_maps() {
    core::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
pub const extern "C" fn trigger_btf_hash_of_maps() {
    core::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
pub const extern "C" fn trigger_btf_array_of_maps_get_value() {
    core::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
pub const extern "C" fn trigger_btf_hash_of_maps_get_value() {
    core::hint::black_box(());
}

/// Test `ArrayOfMaps`: read a value from an inner array via the outer map.
#[uprobe]
pub(crate) fn test_btf_array_of_maps(_ctx: ProbeContext) -> u32 {
    if let Some(ptr) = RESULTS.get_ptr_mut(0) {
        if let Some(inner) = ARRAY_OF_MAPS.get(0) {
            if let Some(val) = inner.get(0) {
                unsafe {
                    (*ptr).value = *val;
                }
            }
        }
        unsafe {
            (*ptr).ran = 1;
        }
    }
    0
}

/// Test `HashOfMaps`: read a value from an inner array via the outer hash map.
#[uprobe]
pub(crate) fn test_btf_hash_of_maps(_ctx: ProbeContext) -> u32 {
    if let Some(ptr) = RESULTS.get_ptr_mut(1) {
        if let Some(inner) = unsafe { HASH_OF_MAPS.get(&0u32) } {
            if let Some(val) = inner.get(0) {
                unsafe {
                    (*ptr).value = *val;
                }
            }
        }
        unsafe {
            (*ptr).ran = 1;
        }
    }
    0
}

/// Test `ArrayOfMaps::get_value` and `get_value_ptr_mut`.
#[uprobe]
pub(crate) fn test_btf_array_of_maps_get_value(_ctx: ProbeContext) -> u32 {
    if let Some(ptr) = RESULTS.get_ptr_mut(2) {
        if let Some(val) = ARRAY_OF_MAPS.get_value(0, &0u32) {
            unsafe {
                (*ptr).value = *val;
            }
        }
        unsafe {
            (*ptr).ran = 1;
        }
    }

    if let Some(ptr) = ARRAY_OF_MAPS.get_value_ptr_mut(1, &0u32) {
        unsafe {
            *ptr = 99;
        }
    }

    0
}

/// Test `HashOfMaps::get_value` and `get_value_ptr_mut`.
#[uprobe]
pub(crate) fn test_btf_hash_of_maps_get_value(_ctx: ProbeContext) -> u32 {
    if let Some(ptr) = RESULTS.get_ptr_mut(3) {
        if let Some(val) = unsafe { HASH_OF_MAPS.get_value(&0u32, &0u32) } {
            unsafe {
                (*ptr).value = *val;
            }
        }
        unsafe {
            (*ptr).ran = 1;
        }
    }

    if let Some(ptr) = unsafe { HASH_OF_MAPS.get_value_ptr_mut(&1u32, &0u32) } {
        unsafe {
            *ptr = 88;
        }
    }

    0
}
