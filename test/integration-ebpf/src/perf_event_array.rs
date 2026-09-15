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
    btf_maps::PerfEventArray as BtfPerfEventArray,
    macros::{btf_map, map, uprobe},
    maps::PerfEventArray as LegacyPerfEventArray,
    programs::ProbeContext,
};

#[btf_map]
static EVENTS: BtfPerfEventArray = BtfPerfEventArray::new();

#[map]
static EVENTS_LEGACY: LegacyPerfEventArray<u64> = LegacyPerfEventArray::new(0);

macro_rules! define_perf_event_array_test {
    ($map:ident, $probe:ident $(,)?) => {
        #[uprobe]
        fn $probe(ctx: ProbeContext) {
            let payload: u64 = 0xDEAD_BEEF;
            $map.output(&ctx, &payload, 0);
        }
    };
}

define_perf_event_array_test!(EVENTS, emit_event);
define_perf_event_array_test!(EVENTS_LEGACY, emit_event_legacy);
