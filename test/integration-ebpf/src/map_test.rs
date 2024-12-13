// Socket Filter program for testing with an arbitrary program with maps.
// This is mainly used in tests with consideration for old kernels.

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::{Array, HashMap},
    programs::SkBuffContext,
};

// Introduced in kernel v3.19.
#[map]
static FOO: Array<u32> = Array::<u32>::with_max_entries(10, 0);

// Introduced in kernel v3.19.
#[map(name = "BAR")]
static BAZ: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(8, 0);

// Introduced in kernel v3.19.
#[socket_filter]
pub fn simple_prog(_ctx: SkBuffContext) -> i64 {
    // So that these maps show up under the `map_ids` field.
    FOO.get(0);
    // If we use the literal value `0` instead of the local variable `i`, then an additional
    // `.rodata` map will be associated with the program.
    let i = 0;
    BAZ.get_ptr(&i);

    0
}

#[xdp]
pub fn foo_map_insert(_ctx: XdpContext) -> u32 {
    FOO.set(0, &1234, 0).ok();
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
