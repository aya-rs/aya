#![no_std]
#![no_main]
#![allow(
    unused_crate_dependencies,
    reason = "ebpf_panic is only required for non-test eBPF builds; importing it unconditionally would register its panic handler during tests and conflict with std"
)]

#[cfg(not(test))]
extern crate ebpf_panic;

// Required for satisfying unused-crate-dependencies lint
#[rustfmt::skip]
use aya_log_ebpf as _;
#[rustfmt::skip]
use integration_ebpf as _;
#[rustfmt::skip]
use integration_common as _;
#[rustfmt::skip]
use network_types as _;

use aya_ebpf::{
    EbpfContext as _, helpers,
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(0, 0);

#[uprobe]
fn uprobe_cookie(ctx: ProbeContext) {
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    let cookie_bytes = cookie.to_ne_bytes();
    let _res = RING_BUF.output::<[u8]>(&cookie_bytes, 0);
}
