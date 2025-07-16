#![no_std]
#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya_ebpf::{
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};
use aya_log_ebpf::{debug, error, info, trace, warn};
use integration_common::log::Buffer;
#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static BUFFER: Array<Buffer> = Array::with_max_entries(1, 0);

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

    // 10.0.0.1
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    // 2001:db8::1
    let ipv6 = Ipv6Addr::new(8193, 3512, 0, 0, 0, 0, 0, 1);
    info!(
        &ctx,
        "ip structs, without format hint: ipv4: {}, ipv6: {}", ipv4, ipv6
    );
    info!(
        &ctx,
        "ip structs, with format hint: ipv4: {:i}, ipv6: {:i}", ipv4, ipv6
    );

    let ipv4_enum = IpAddr::V4(ipv4);
    let ipv6_enum = IpAddr::V6(ipv6);
    info!(
        &ctx,
        "ip enums, without format hint: ipv4: {}, ipv6: {}", ipv4_enum, ipv6_enum
    );
    info!(
        &ctx,
        "ip enums, with format hint: ipv4: {:i}, ipv6: {:i}", ipv4_enum, ipv6_enum
    );

    // We don't format `Ipv6Addr::to_bits`, because `u128` is not supported by
    // eBPF. Even though Rust compiler does not complain, verifier would throw
    // an error about returning values not fitting into 64-bit registers.
    info!(&ctx, "ip as bits: ipv4: {:i}", ipv4.to_bits());

    info!(
        &ctx,
        "ip as octets: ipv4: {:i}, ipv6: {:i}",
        ipv4.octets(),
        ipv6.octets()
    );

    let mac = [4u8, 32u8, 6u8, 9u8, 0u8, 64u8];
    trace!(&ctx, "mac lc: {:mac}, mac uc: {:MAC}", mac, mac);
    let hex = 0x2f;
    warn!(&ctx, "hex lc: {:x}, hex uc: {:X}", hex, hex);
    let hex = [0xde, 0xad, 0xbe, 0xef].as_slice();
    debug!(&ctx, "hex lc: {:x}, hex uc: {:X}", hex, hex);
    let header = 42;
    let tmp = 43;
    let kind = 44;
    let value = 45;
    let size = 46;
    let op = 47;
    let buf = 48;
    debug!(
        &ctx,
        "{} {} {} {} {} {} {}", header, tmp, kind, value, size, op, buf
    );

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

    let Some(ptr) = BUFFER.get_ptr_mut(0) else {
        return;
    };
    let src = unsafe { ptr.as_ref() };
    let Some(Buffer { buf, len }) = src else {
        return;
    };
    let len = *len;
    let buf = if len < buf.len() {
        &buf[..len]
    } else {
        &buf[..]
    };
    info!(&ctx, "variable length buffer: {:x}", buf);
}
