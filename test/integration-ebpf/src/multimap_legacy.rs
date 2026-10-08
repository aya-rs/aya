#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

#[map(name = "map_1")]
static MAP_1: Array<u64> = Array::with_max_entries(1, 0);

#[map(name = "map_2")]
static MAP_2: Array<u64> = Array::with_max_entries(1, 0);

#[map(name = "map_pin_by_name")]
static MAP_PIN_BY_NAME: Array<u64> = Array::pinned(1, 0);

#[uprobe]
fn bpf_prog(_ctx: ProbeContext) -> Result<(), i32> {
    MAP_1.set(0, &24, 0)?;
    MAP_2.set(0, &42, 0)?;
    MAP_PIN_BY_NAME.set(0, &44, 0)
}
