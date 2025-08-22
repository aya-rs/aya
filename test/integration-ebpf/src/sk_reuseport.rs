#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, sk_reuseport},
    maps::ReusePortSockArray,
    programs::{SK_PASS, SK_DROP, SkReuseportContext},
    helpers::bpf_sk_select_reuseport,
    EbpfContext as _,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map(name = "socket_map")]
static SOCKET_MAP: ReusePortSockArray = ReusePortSockArray::with_max_entries(10, 0);

#[sk_reuseport]
pub fn select_socket(_ctx: SkReuseportContext) -> u32 {
    // Return SK_PASS to allow packet and let kernel handle socket selection
    // Return SK_DROP would drop the packet
    SK_PASS
}

#[sk_reuseport]
pub fn test_context_access(ctx: SkReuseportContext) -> u32 {
    // Test accessing context fields
    let _len = ctx.len();
    let _hash = ctx.hash();
    let _ip_protocol = ctx.ip_protocol();
    let _eth_protocol = ctx.eth_protocol();
    let _bind_inany = ctx.bind_inany();
    let _data = ctx.data();
    let _data_end = ctx.data_end();

    // Always pass for testing
    SK_PASS
}

#[sk_reuseport]
pub fn test_helper_usage(ctx: SkReuseportContext) -> u32 {
    // Use hash-based socket selection with helper
    let socket_idx = ctx.hash() % 4;
    
    // Only handle TCP traffic (protocol 6)
    if ctx.ip_protocol() == 6 {
        let ret = unsafe {
            bpf_sk_select_reuseport(
                ctx.as_ptr() as *mut _,
                SOCKET_MAP.as_ptr(),
                &socket_idx as *const _ as *mut _,
                0
            )
        };
        
        // Return result based on helper success
        if ret == 0 {
            SK_PASS
        } else {
            SK_DROP
        }
    } else {
        // Let kernel handle non-TCP traffic
        SK_PASS
    }
}
