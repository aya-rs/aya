#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::Array,
    macros::{btf_map, xdp},
    programs::XdpContext,
    spin_lock::EbpfSpinLock as _,
};
use integration_common::spin_lock::Counter;

#[btf_map]
static COUNTER: Array<Counter, 1> = Array::new();

#[xdp]
fn packet_counter(_ctx: XdpContext) -> u32 {
    let Some(counter) = COUNTER.get_ptr_mut(0) else {
        return xdp_action::XDP_PASS;
    };
    let counter = unsafe { &mut *counter };
    {
        let _guard = counter.spin_lock.lock();
        counter.count = counter.count.saturating_add(1);
    }

    xdp_action::XDP_PASS
}
