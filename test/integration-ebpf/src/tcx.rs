#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::tcx_action_base::{TCX_NEXT, TCX_PASS},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[no_mangle]
static ORDER: i32 = 0;

// Gives us raw pointers to a specific offset in the packet
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, i64> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TCX_PASS.into());
    }
    Ok((start + offset) as *mut T)
}

#[classifier]
pub fn tcx_order(ctx: TcContext) -> i32 {
    match try_tcxtest(ctx) {
        Ok(ret) => ret,
        Err(_ret) => TCX_PASS,
    }
}

fn try_tcxtest(ctx: TcContext) -> Result<i32, i64> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0) }?;
    let order = unsafe { core::ptr::read_volatile(&ORDER) };
    match unsafe { *eth_hdr }.ether_type {
        EtherType::Ipv4 => {
            let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let saddr = u32::from_be(unsafe { (*ipv4_hdr).src_addr });
            let daddr = u32::from_be(unsafe { (*ipv4_hdr).dst_addr });
            match unsafe { (*ipv4_hdr).proto } {
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    let dport = u16::from_be(unsafe { (*udphdr).dest });
                    let sport = u16::from_be(unsafe { (*udphdr).source });
                    info!(
                        &ctx,
                        "order: {}, cookie: ({:i}, {:i}, {}, {})",
                        order,
                        daddr,
                        saddr,
                        dport,
                        sport
                    );

                    Ok(TCX_NEXT)
                }
                _ => Ok(TCX_PASS),
            }
        }
        _ => Ok(TCX_PASS),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
