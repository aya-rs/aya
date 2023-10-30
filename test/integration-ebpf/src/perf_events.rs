#![no_std]
#![no_main]

use aya_bpf::{
    bindings::bpf_perf_event_value,
    helpers::bpf_get_smp_processor_id,
    macros::{map, perf_event},
    maps::PerfEventArray,
    programs::PerfEventContext,
};

#[repr(C)]
struct EventData {
    value: u64,
    cpu_id: u32,
    tag: u8,
}

/// Input map: file descriptors of the perf events, obtained by calling
/// `perf_event_open` in user space.
#[map]
static mut DESCRIPTORS: PerfEventArray<i32> = PerfEventArray::with_max_entries(1, 0);

#[map]
static mut OUTPUT: PerfEventArray<EventData> = PerfEventArray::with_max_entries(1, 0);

#[perf_event]
pub fn on_perf_event(ctx: PerfEventContext) -> i64 {
    match read_event(&ctx).map(|res| write_output(&ctx, res)) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

fn read_event(ctx: &PerfEventContext) -> Result<EventData, i64> {
    // read the event value using the file descriptor in the DESCRIPTORS array
    let event: bpf_perf_event_value = unsafe { DESCRIPTORS.read_current_cpu() }?;

    let cpu_id = unsafe { bpf_get_smp_processor_id() };
    let res = EventData {
        value: event.counter,
        cpu_id,
        tag: 0xAB,
    };
    Ok(res)
}

fn write_output(ctx: &PerfEventContext, output: EventData) -> Result<(), i64> {
    unsafe { OUTPUT.output_current_cpu(ctx, &output) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
