#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::PerfEventArray as BtfPerfEventArray,
    macros::{btf_map, map, uprobe},
    maps::PerfEventArray as LegacyPerfEventArray,
    programs::ProbeContext,
};

#[btf_map]
static EVENTS: BtfPerfEventArray<0, 0> = BtfPerfEventArray::new();

#[btf_map]
static COUNTERS: BtfPerfEventArray<2, 0> = BtfPerfEventArray::new();

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

#[uprobe]
fn read_counter(ctx: ProbeContext) {
    if let (Ok(task_clock), Ok(cpu_clock)) = (COUNTERS.read_value(0), COUNTERS.read_value(1)) {
        EVENTS.output(&ctx, &[task_clock, cpu_clock], 0);
    }
}
