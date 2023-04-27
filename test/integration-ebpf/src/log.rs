#![no_std]
#![no_main]

use aya_bpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::{debug, error, info, trace, warn};

#[uprobe]
pub fn test_log(ctx: ProbeContext) {
    debug!(&ctx, "Hello from eBPF!");
    error!(&ctx, "{}, {}, {}", 69, 420i32, "wao");
    let ipv4 = 167772161u32; // 10.0.0.1
    let ipv6 = [
        32u8, 1u8, 13u8, 184u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8,
    ]; // 2001:db8::1
    info!(&ctx, "ipv4: {:ipv4}, ipv6: {:ipv6}", ipv4, ipv6);
    let mac = [4u8, 32u8, 6u8, 9u8, 0u8, 64u8];
    trace!(&ctx, "mac lc: {:mac}, mac uc: {:MAC}", mac, mac);
    let hex = 0x2f;
    warn!(&ctx, "hex lc: {:x}, hex uc: {:X}", hex, hex);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
