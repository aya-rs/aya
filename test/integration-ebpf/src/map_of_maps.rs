#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, uprobe},
    maps::{Array, ArrayOfMaps, HashMap, HashOfMaps},
    programs::ProbeContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

// ArrayOfMaps test maps - explicitly bind to INNER_ARRAY_1 as template
#[map(inner = "INNER_ARRAY_1")]
static ARRAY_OF_MAPS: ArrayOfMaps<Array<u32>> = ArrayOfMaps::with_max_entries(2, 0);

#[map]
static INNER_ARRAY_1: Array<u32> = Array::with_max_entries(10, 0);

#[map]
static INNER_ARRAY_2: Array<u32> = Array::with_max_entries(10, 0);

// HashOfMaps test maps - explicitly bind to INNER_HASH_1 as template
#[map(inner = "INNER_HASH_1")]
static HASH_OF_MAPS: HashOfMaps<u32, HashMap<u32, u32>> = HashOfMaps::with_max_entries(2, 0);

#[map]
static INNER_HASH_1: HashMap<u32, u32> = HashMap::with_max_entries(10, 0);

#[map]
static INNER_HASH_2: HashMap<u32, u32> = HashMap::with_max_entries(10, 0);

// Result array to verify values from userspace
#[map]
static RESULTS: Array<u32> = Array::with_max_entries(4, 0);

#[unsafe(no_mangle)]
#[inline(never)]
#[expect(
    clippy::missing_const_for_fn,
    reason = "extern functions cannot be const"
)]
pub extern "C" fn trigger_array_of_maps() {
    core::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
#[expect(
    clippy::missing_const_for_fn,
    reason = "extern functions cannot be const"
)]
pub extern "C" fn trigger_hash_of_maps() {
    core::hint::black_box(());
}

/// Test `ArrayOfMaps`: write values to inner arrays via outer map
#[uprobe]
pub(crate) fn test_array_of_maps(_ctx: ProbeContext) -> u32 {
    // Access first inner map (index 0) and write value
    if let Some(map) = ARRAY_OF_MAPS.get(0) {
        if let Some(ptr) = map.get_ptr_mut(0) {
            unsafe {
                *ptr = 42;
            }
        }
    }

    // Access second inner map (index 1) and write value
    if let Some(map) = ARRAY_OF_MAPS.get(1) {
        if let Some(ptr) = map.get_ptr_mut(0) {
            unsafe {
                *ptr = 24;
            }
        }
    }

    // Store results for verification
    if let Some(ptr) = RESULTS.get_ptr_mut(0) {
        unsafe {
            *ptr = 1;
        } // Mark test ran
    }

    0
}

/// Test `HashOfMaps`: write values to inner hashmaps via outer map
#[uprobe]
pub(crate) fn test_hash_of_maps(_ctx: ProbeContext) -> u32 {
    // Access first inner map (key 0) and write value
    if let Some(map) = unsafe { HASH_OF_MAPS.get(&0u32) } {
        _ = map.insert(100u32, 42u32, 0);
    }

    // Access second inner map (key 1) and write value
    if let Some(map) = unsafe { HASH_OF_MAPS.get(&1u32) } {
        _ = map.insert(100u32, 24u32, 0);
    }

    // Store results for verification
    if let Some(ptr) = RESULTS.get_ptr_mut(1) {
        unsafe {
            *ptr = 1;
        } // Mark test ran
    }

    0
}
