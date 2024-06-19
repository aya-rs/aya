#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, uprobe},
    maps::{PerfEventArray, RingBuf},
    programs::ProbeContext,
};

#[no_mangle]
pub static RINGBUF_SUPPORTED: i32 = 0;

#[map]
static mut RINGBUF: RingBuf = RingBuf::with_byte_size(0, 0);

#[map]
static mut PERFBUF: PerfEventArray<u64> = PerfEventArray::with_max_entries(1, 0);

#[uprobe]
pub fn test_ignored_map_relocation(ctx: ProbeContext) {
    if unsafe { core::ptr::read_volatile(&RINGBUF_SUPPORTED) == 1 } {
        let _ = unsafe { RINGBUF.output(&1, 0).map_err(|_| 1u32) };
    } else {
        unsafe { PERFBUF.output(&ctx, &1, 0) };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
