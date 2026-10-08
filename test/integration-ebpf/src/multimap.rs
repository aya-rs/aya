#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::Array,
    macros::{btf_map, map, uprobe},
    maps::Array as LegacyArray,
    programs::ProbeContext,
};

#[btf_map(name = "map_1")]
static MAP_1: Array<u64, 1> = Array::new();

#[btf_map(name = "map_2")]
static MAP_2: Array<u64, 1> = Array::new();

#[btf_map(name = "map_pin_by_name", pin_by_name)]
static MAP_PIN_BY_NAME: Array<u64, 1> = Array::new();

#[map(name = "map_1_legacy")]
static MAP_1_LEGACY: LegacyArray<u64> = LegacyArray::with_max_entries(1, 0);

#[map(name = "map_2_legacy")]
static MAP_2_LEGACY: LegacyArray<u64> = LegacyArray::with_max_entries(1, 0);

#[map(name = "map_pin_by_name_legacy")]
static MAP_PIN_BY_NAME_LEGACY: LegacyArray<u64> = LegacyArray::pinned(1, 0);

#[uprobe]
fn bpf_prog(_ctx: ProbeContext) -> Result<(), i32> {
    macro_rules! set {
        ($value:expr, $btf:ident, $legacy:ident) => {
            // Local values keep the object free of promoted .rodata maps.
            let value = $value;
            $btf.set(0, &value, 0)?;
            $legacy.set(0, &value, 0)?;
        };
    }
    set!(24, MAP_1, MAP_1_LEGACY);
    set!(42, MAP_2, MAP_2_LEGACY);
    set!(44, MAP_PIN_BY_NAME, MAP_PIN_BY_NAME_LEGACY);
    Ok(())
}
