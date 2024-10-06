#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        xdp_action::{self, XDP_DROP, XDP_PASS},
        BPF_F_NO_PREALLOC,
    },
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};
#[xdp]
pub fn xdp_syncookie(ctx: XdpContext) -> u32 {
    match try_xdp_syncookie(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct TupleIPv4 {
    pub src_address: u32,
    pub dst_address: u32,
    pub dst_port: u16,
}
impl TupleIPv4 {
    fn new(ipv4hdr: *mut Ipv4Hdr, tcphdr: *mut TcpHdr) -> TupleIPv4 {
        unsafe {
            TupleIPv4 {
                src_address: (*ipv4hdr).src_addr,
                dst_address: (*ipv4hdr).dst_addr,
                dst_port: (*tcphdr).dest,
            }
        }
    }
}
#[map]
static VERIFIED_TUPLES_V4: HashMap<TupleIPv4, u8> = HashMap::<TupleIPv4, u8>::with_max_entries(1000000, BPF_F_NO_PREALLOC);

#[map]
pub static IPS_WHO_HAS_SENT_SYN_BUT_DIDNT_SEND_ACK_YET: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(2000000, BPF_F_NO_PREALLOC);

fn try_xdp_syncookie(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(XDP_PASS);
    }
    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        return Ok(XDP_PASS);
    }
    unsafe {
        let tcphdr: *mut TcpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

        if 25565 != u16::from_be((*tcphdr).dest) {
            return Ok(XDP_PASS);
        }
        info!(&ctx, "-------------{:i}-------------", src_addr,);
        let data_payload_len = u16::from_be((*ipv4hdr).tot_len) as u32 - (*ipv4hdr).ihl() as u32 * 4 - (*tcphdr).doff() as u32 * 4;

        if is_handshake_syn_packet(tcphdr, &data_payload_len) {
            handle_syn_packet(&ctx, ipv4hdr, tcphdr, &data_payload_len, &src_addr)
        } else if is_handshake_ack_packet(tcphdr, (*ipv4hdr).src_addr, &data_payload_len) {
            handle_ack_packet(&ctx, ipv4hdr, tcphdr, &data_payload_len, &src_addr)
        } else {
            let tuple_ipv4 = TupleIPv4::new(ipv4hdr, tcphdr);

            info!(
                &ctx,
                "{} non-handshake received tuple {:i} {:i} {}, {} {} {}",
                bpf_ktime_get_ns(),
                u32::from_be(tuple_ipv4.src_address),
                u32::from_be(tuple_ipv4.dst_address),
                u16::from_be(tuple_ipv4.dst_port),
                tuple_ipv4.src_address,
                tuple_ipv4.dst_address,
                tuple_ipv4.dst_port,
            );
            if VERIFIED_TUPLES_V4.get(&tuple_ipv4).is_some() {
                info!(&ctx, "tuple was in the map");
                return Ok(XDP_DROP);
            } else {
                info!(&ctx, "tuple was not in the map", src_addr);
                Ok(XDP_PASS)
            }
        }
    }
}
unsafe fn handle_syn_packet(ctx: &XdpContext, ipv4hdr: *mut Ipv4Hdr, tcphdr: *mut TcpHdr, data_payload_len: &u32, src_addr: &u32) -> Result<u32, ()> {
    info!(
        ctx,
        "Received SYN packet {:i} seq {} ack_seq {} data_len {}",
        *src_addr,
        u32::from_be((*tcphdr).seq),
        u32::from_be((*tcphdr).ack_seq),
        *data_payload_len,
    );
    if IPS_WHO_HAS_SENT_SYN_BUT_DIDNT_SEND_ACK_YET.insert(&(*ipv4hdr).src_addr, &0, 0).is_err() {
        info!(ctx, "Exceeded amount of syn map limit. just increase it...............................");
        return Ok(XDP_DROP);
    }
    Ok(XDP_PASS)
}

unsafe fn handle_ack_packet(ctx: &XdpContext, ipv4hdr: *mut Ipv4Hdr, tcphdr: *mut TcpHdr, data_payload_len: &u32, src_addr: &u32) -> Result<u32, ()> {
    info!(
        ctx,
        "Received ACK packet {:i}, seq {} ack_seq {} len: {}",
        *src_addr,
        u32::from_be((*tcphdr).seq),
        u32::from_be((*tcphdr).ack_seq),
        *data_payload_len
    );
    let tuple_ipv4 = TupleIPv4::new(ipv4hdr, tcphdr);

    info!(
        ctx,
        "{} received tuple {:i} {:i} {}, {} {} {}",
        bpf_ktime_get_ns(),
        u32::from_be(tuple_ipv4.src_address),
        u32::from_be(tuple_ipv4.dst_address),
        u16::from_be(tuple_ipv4.dst_port),
        tuple_ipv4.src_address,
        tuple_ipv4.dst_address,
        tuple_ipv4.dst_port,
    );
    info!(
        ctx,
        "{} stored tuple {:i} {:i} {}, {} {} {}",
        bpf_ktime_get_ns(),
        u32::from_be(tuple_ipv4.src_address),
        u32::from_be(tuple_ipv4.dst_address),
        u16::from_be(tuple_ipv4.dst_port),
        tuple_ipv4.src_address,
        tuple_ipv4.dst_address,
        tuple_ipv4.dst_port,
    );
    if VERIFIED_TUPLES_V4.insert(&tuple_ipv4, &0, 0).is_err() {
        info!(ctx, "Exceded max amount of tuple entries. connections might get dropped.");
        return Ok(XDP_DROP);
    }

    Ok(XDP_PASS)
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

#[inline(always)]
pub unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *mut T;
    Ok(ptr)
}
fn is_handshake_syn_packet(tcphdr: *mut TcpHdr, data_payload_len: &u32) -> bool {
    unsafe {
        (*tcphdr).ack() == 0
            && (*tcphdr).syn() == 1
            && data_payload_len == &0
            && (*tcphdr).fin() == 0
            && (*tcphdr).rst() == 0
            && (*tcphdr).psh() == 0
            && (*tcphdr).urg() == 0
            && (*tcphdr).cwr() == 0
            && (*tcphdr).ece() == 0
    }
}
fn is_handshake_ack_packet(tcphdr: *mut TcpHdr, src_addr: u32, data_payload_len: &u32) -> bool {
    unsafe {
        let result = IPS_WHO_HAS_SENT_SYN_BUT_DIDNT_SEND_ACK_YET.get(&src_addr).is_some()
            && (*tcphdr).ack() == 1
            && (*tcphdr).syn() == 0
            && data_payload_len == &0
            && (*tcphdr).fin() == 0
            && (*tcphdr).rst() == 0
            && (*tcphdr).psh() == 0
            && (*tcphdr).urg() == 0
            && (*tcphdr).cwr() == 0
            && (*tcphdr).ece() == 0;
        if result {
            IPS_WHO_HAS_SENT_SYN_BUT_DIDNT_SEND_ACK_YET.remove(&src_addr).unwrap_or_default();
        }
        result
    }
}
