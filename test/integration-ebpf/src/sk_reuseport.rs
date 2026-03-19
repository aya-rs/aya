#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    macros::{map, sk_reuseport},
    maps::{Array, ReusePortSockArray},
    programs::{SK_DROP, SK_PASS, SkReuseportContext},
};
#[cfg(not(test))]
extern crate ebpf_panic;

const SOCKET_COUNT: u32 = 10;
const IPPROTO_TCP: u32 = 6;

// Keep these test-only indices aligned with the userspace assertions in
// `test/integration-test/src/tests/sk_reuseport.rs`; the eBPF test binary and
// the userspace test crate are built separately, so they cannot share one Rust
// definition directly.
const SELECT_HITS_INDEX: u32 = 0;
const MIGRATE_HITS_INDEX: u32 = 1;
const CLEAR_FALLBACK_HITS_INDEX: u32 = 2;
const SELECT_SOCKET_INDEX: u32 = 0;
const MIGRATE_SOCKET_INDEX: u32 = 2;

#[map(name = "socket_map")]
static SOCKET_MAP: ReusePortSockArray = ReusePortSockArray::with_max_entries(SOCKET_COUNT, 0);

#[map(name = "path_hits")]
// Test-only counters used to verify that the expected BPF path actually ran,
// instead of the kernel falling back to its default reuseport selection logic.
static PATH_HITS: Array<u64> = Array::with_max_entries(3, 0);

#[inline]
fn record_hit(index: u32) {
    let Some(hit) = PATH_HITS.get_ptr_mut(index) else {
        return;
    };

    unsafe {
        *hit += 1;
    }
}

#[sk_reuseport]
fn select_socket(ctx: SkReuseportContext) -> u32 {
    if ctx.data() >= ctx.data_end() || ctx.ip_protocol() != IPPROTO_TCP {
        return SK_PASS;
    }

    record_hit(SELECT_HITS_INDEX);

    match ctx.select_reuseport(&SOCKET_MAP, SELECT_SOCKET_INDEX, 0) {
        Ok(()) => SK_PASS,
        Err(_) => SK_DROP,
    }
}

#[sk_reuseport]
fn select_socket_after_clear(ctx: SkReuseportContext) -> u32 {
    if ctx.data() >= ctx.data_end() || ctx.ip_protocol() != IPPROTO_TCP {
        return SK_PASS;
    }

    match ctx.select_reuseport(&SOCKET_MAP, SELECT_SOCKET_INDEX, 0) {
        Ok(()) => {
            record_hit(SELECT_HITS_INDEX);
            SK_PASS
        }
        Err(_) => match ctx.select_reuseport(&SOCKET_MAP, MIGRATE_SOCKET_INDEX, 0) {
            Ok(()) => {
                record_hit(CLEAR_FALLBACK_HITS_INDEX);
                SK_PASS
            }
            Err(_) => SK_DROP,
        },
    }
}

#[sk_reuseport(migrate)]
fn select_or_migrate_socket(ctx: SkReuseportContext) -> u32 {
    if ctx.ip_protocol() != IPPROTO_TCP {
        return SK_PASS;
    }

    let sk = ctx.sk();
    if sk.sock.is_null() {
        return SK_DROP;
    }
    let socket_idx = if ctx.migrating_sk().is_some() {
        // The kernel may invoke the migrate path with an empty skb, so
        // `data()` and `data_end()` are not reliable discriminators here.
        record_hit(MIGRATE_HITS_INDEX);
        MIGRATE_SOCKET_INDEX
    } else {
        if ctx.data() >= ctx.data_end() {
            return SK_PASS;
        }
        record_hit(SELECT_HITS_INDEX);
        SELECT_SOCKET_INDEX
    };

    match ctx.select_reuseport(&SOCKET_MAP, socket_idx, 0) {
        Ok(()) => SK_PASS,
        Err(_) => SK_DROP,
    }
}
