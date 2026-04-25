#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::PerfEventByteArray as BtfPerfEventByteArray,
    macros::{btf_map, map, uprobe},
    maps::PerfEventByteArray as LegacyPerfEventByteArray,
    programs::ProbeContext,
};

#[btf_map]
static EVENTS: BtfPerfEventByteArray = BtfPerfEventByteArray::new();

#[map]
static EVENTS_LEGACY: LegacyPerfEventByteArray = LegacyPerfEventByteArray::new(0);

macro_rules! define_perf_event_byte_array_test {
    ($map:ident, $probe:ident $(,)?) => {
        #[uprobe]
        fn $probe(ctx: ProbeContext) {
            let payload = 0xDEAD_BEEFu64.to_ne_bytes();
            $map.output(&ctx, &payload, 0);
        }
    };
}

define_perf_event_byte_array_test!(EVENTS, emit_event);
define_perf_event_byte_array_test!(EVENTS_LEGACY, emit_event_legacy);
