#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    bindings::sk_action::{SK_DROP, SK_PASS},
    btf_maps::{Array, SockHash as BtfSockHash},
    macros::{btf_map, map, sk_lookup},
    maps::SockHash as LegacySockHash,
    programs::SkLookupContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;

#[map(name = "SOCKETS_LEGACY")]
static SOCKETS_LEGACY: LegacySockHash<u32> = LegacySockHash::with_max_entries(1, 0);

#[btf_map(name = "SOCKETS_BTF")]
static SOCKETS_BTF: BtfSockHash<u32, 1> = BtfSockHash::new();

#[btf_map(name = "LAST_ERRNO")]
static LAST_ERRNO: Array<i32, 1> = Array::new();

macro_rules! define_sk_lookup {
    ($map:ident, $prog:ident) => {
        #[sk_lookup]
        fn $prog(ctx: SkLookupContext) -> u32 {
            match $map.redirect_sk_lookup(&ctx, 0u32, 0) {
                Ok(()) => SK_PASS,
                Err(errno) => match LAST_ERRNO.set(0, errno, 0) {
                    // Single-slot ARRAY set is infallible at runtime.
                    Ok(()) | Err(_) => SK_DROP,
                },
            }
        }
    };
}

define_sk_lookup!(SOCKETS_LEGACY, sk_lookup_legacy);
define_sk_lookup!(SOCKETS_BTF, sk_lookup_btf);
