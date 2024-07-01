#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv6Hdr,
};

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

struct Value {
    pub orig_ip: [u8; 16],
}

#[map]
static RULES: HashMap<u8, Value> = HashMap::<u8, Value>::with_max_entries(1, BPF_F_NO_PREALLOC);

#[xdp]
pub fn do_dnat(ctx: XdpContext) -> u32 {
    try_do_dnat(ctx).unwrap_or(xdp_action::XDP_DROP)
}

fn try_do_dnat(ctx: XdpContext) -> Result<u32, ()> {
    let index = 0;
    if let Some(nat) = unsafe { RULES.get(&index) } {
        let hproto: *const EtherType = ptr_at(&ctx, mem::offset_of!(EthHdr, ether_type))?;
        match unsafe { *hproto } {
            EtherType::Ipv6 => {
                let ip_hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
                unsafe { (*ip_hdr.cast_mut()).dst_addr.in6_u.u6_addr8 = nat.orig_ip };
            }
            _ => return Ok(xdp_action::XDP_PASS),
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
