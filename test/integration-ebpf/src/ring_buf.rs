#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
use core::mem::size_of;

// Make a buffer large enough to hold MAX_ENTRIES entries at the same time.
// This requires taking into consideration the header size.
type Entry = u64;
const MAX_ENTRIES: usize = 1024;
const HDR_SIZE: usize = aya_bpf::bindings::BPF_RINGBUF_HDR_SZ as usize;

// Add 1 because the capacity at any given time is actually one less than
// you might think because the consumer_pos and producer_pos being equal
// would mean that the buffer is empty. The synchronous test fills the
// buffer, hence this logic.
const RING_BUF_SIZE: usize = ((size_of::<Entry>() + HDR_SIZE) * MAX_ENTRIES) + 1;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE as u32, 0);

#[uprobe]
pub fn ring_buf_test(ctx: ProbeContext) {
    // Write the first argument to the function back out to RING_BUF.
    let arg: Entry = match ctx.arg(0) {
        Some(arg) => arg,
        None => return,
    };
    if let Some(mut entry) = RING_BUF.reserve::<Entry>(0) {
        entry.write(arg);
        entry.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
