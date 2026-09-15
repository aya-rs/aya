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
    bindings::sk_action::{SK_DROP, SK_PASS},
    btf_maps::{Array, SockMap as BtfSockMap},
    macros::{btf_map, map, sk_lookup},
    maps::SockMap as LegacySockMap,
    programs::SkLookupContext,
};

#[map(name = "SOCKETS_LEGACY")]
static SOCKETS_LEGACY: LegacySockMap = LegacySockMap::with_max_entries(1, 0);

#[btf_map(name = "SOCKETS_BTF")]
static SOCKETS_BTF: BtfSockMap<1> = BtfSockMap::new();

#[btf_map(name = "LAST_ERRNO")]
static LAST_ERRNO: Array<i32, 1> = Array::new();

macro_rules! define_sk_lookup {
    ($map:ident, $prog:ident) => {
        #[sk_lookup]
        fn $prog(ctx: SkLookupContext) -> u32 {
            match $map.redirect_sk_lookup(&ctx, 0, 0) {
                Ok(()) => SK_PASS,
                Err(errno) => match LAST_ERRNO.set(0, &errno, 0) {
                    // Single-slot ARRAY set is infallible at runtime.
                    Ok(()) | Err(_) => SK_DROP,
                },
            }
        }
    };
}

define_sk_lookup!(SOCKETS_LEGACY, sk_lookup_legacy);
define_sk_lookup!(SOCKETS_BTF, sk_lookup_btf);
