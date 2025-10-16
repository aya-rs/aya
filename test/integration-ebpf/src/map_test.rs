#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, socket_filter, uprobe},
    maps::{Array, HashMap},
    programs::{ProbeContext, SkBuffContext},
};
#[cfg(not(test))]
extern crate ebpf_panic;

// Introduced in kernel v3.19.
#[map]
static FOO: Array<u32> = Array::<u32>::with_max_entries(10, 0);

// Introduced in kernel v3.19.
#[map(name = "BAR")]
static BAZ: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(8, 0);

// The limit of map names is 16 (including a NUL byte). Ensure that we are
// able to create maps with names exceeding that limit by truncating them.
#[map(name = "MAP_WITH_LOOOONG_NAAAAAAAAME")]
static MAP_WITH_LOOOONG_NAAAAAAAAME: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(8, 0);

// Introduced in kernel v3.19.
#[socket_filter]
fn simple_prog(_ctx: SkBuffContext) -> i64 {
    // So that these maps show up under the `map_ids` field.
    FOO.get(0);
    // If we use the literal value `0` instead of the local variable `i`, then an additional
    // `.rodata` map will be associated with the program.
    let i = 0;
    BAZ.get_ptr(i);

    0
}

#[uprobe]
fn simple_prog_mut(_ctx: ProbeContext) -> i64 {
    if let Some(foo) = FOO.get_ptr_mut(0) {
        unsafe {
            *foo += 1;
        }
    }

    if let Some(baz) = BAZ.get_ptr_mut(0) {
        unsafe {
            *baz += 1;
        }
    }

    0
}
