#![no_std]
#![no_main]

use aya_ebpf::{macros::map, maps::inode_storage::InodeStorage};

#[map]
static INODE_STORE: InodeStorage<usize> = InodeStorage::new(0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
