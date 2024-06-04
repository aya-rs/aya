#![no_std]
#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::{debug, error, info, trace, warn};

#[uprobe]
pub fn test_log(ctx: ProbeContext) {
    debug!(&ctx, "Hello from eBPF!");
    error!(
        &ctx,
        "{}, {}, {}, {:x}",
        69,
        420i32,
        "wao",
        "wao".as_bytes()
    );
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let ipv6 = Ipv6Addr::new(8193, 3512, 0, 0, 0, 0, 0, 1);
    info!(&ctx, "ip structs: ipv4: {:i}, ipv6: {:i}", ipv4, ipv6); // 2001:db8::1
    let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(8193, 3512, 0, 0, 0, 0, 0, 1));
    info!(&ctx, "ip enums: ipv4: {:i}, ipv6: {:i}", ipv4, ipv6);
    let ipv4 = 167772161u32; // 10.0.0.1
    let ipv6 = [
        32u8, 1u8, 13u8, 184u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8,
    ]; // 2001:db8::1
    info!(&ctx, "ip as primitives: ipv4: {:i}, ipv6: {:i}", ipv4, ipv6);
    let mac = [4u8, 32u8, 6u8, 9u8, 0u8, 64u8];
    trace!(&ctx, "mac lc: {:mac}, mac uc: {:MAC}", mac, mac);
    let hex = 0x2f;
    warn!(&ctx, "hex lc: {:x}, hex uc: {:X}", hex, hex);
    let hex = [0xde, 0xad, 0xbe, 0xef].as_slice();
    debug!(&ctx, "hex lc: {:x}, hex uc: {:X}", hex, hex);
    let len = 42;
    let size = 43;
    let slice = 44;
    let record = 45;
    debug!(&ctx, "{} {} {} {}", len, size, slice, record);

    // Testing compilation only.
    if false {
        struct NoCopy {}

        impl NoCopy {
            fn consume(self) -> u64 {
                0xdeadbeef
            }
        }

        let no_copy = NoCopy {};

        debug!(&ctx, "{:x}", no_copy.consume());
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
