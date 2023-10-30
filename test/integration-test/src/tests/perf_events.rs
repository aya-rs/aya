use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use aya::maps::PerfEventArray;
use aya::programs::perf_event::{perf_event_open, PerfEventScope};
use aya::programs::{PerfEvent, PerfTypeId, SamplePolicy};
use aya::Bpf;
use aya_obj::generated::{perf_hw_id, perf_sw_ids, perf_type_id};
use bytes::BytesMut;
use test_log::test;

#[derive(Debug)]
#[repr(C)]
struct EventData {
    value: u64,
    cpu_id: u32,
    tag: u8,
}

#[test]
fn perf_event_read_from_kernel() {
    // load bpf program
    let mut bpf = Bpf::load(crate::PERF_EVENTS).expect("failed to load bpf code");
    let mut descriptors = PerfEventArray::try_from(bpf.take_map("DESCRIPTORS").unwrap()).unwrap();
    let mut bpf_output = PerfEventArray::try_from(bpf.take_map("OUTPUT").unwrap()).unwrap();

    // open a perf_event
    // Beware: this returns an `OwnedFd`, which means that the file descriptor is closed at the end of the scope
    const CPU_ID: u32 = 0;
    let event_fd: OwnedFd = perf_event_open(
        perf_type_id::PERF_TYPE_HARDWARE as u32,
        perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64,
        PerfEventScope::AllProcessesOneCpu { cpu: CPU_ID },
        None,
        None,
        0,
    )
    .unwrap();

    // pass pointer to bpf array
    descriptors.set(0, event_fd.as_raw_fd()).expect("failed to put event's fd into the map");

    // load program
    let program: &mut PerfEvent = bpf
        .program_mut("on_perf_event")
        .unwrap()
        .try_into()
        .unwrap();

    program.load().expect("the bpf program should load properly");

    // get buffer to poll the events
    const BUF_PAGE_COUNT: usize = 1;
    let mut buf = bpf_output
        .open(CPU_ID, Some(BUF_PAGE_COUNT))
        .expect("failed to open output buffer to poll events");

    // attach program
    program
        .attach(
            PerfTypeId::Software,
            perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            PerfEventScope::AllProcessesOneCpu { cpu: CPU_ID },
            SamplePolicy::Frequency(1),
        )
        .expect("the bpf program should attach properly");

    // sleep a little bit, then poll the values from the buffer
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        buf.readable(),
        "the buffer should have been filled by the bpf program"
    );

    // read the events and check that the returned data is correct
    let mut events_data: [BytesMut; BUF_PAGE_COUNT] = std::array::from_fn(|_| BytesMut::new());
    let event_stats = buf.read_events(&mut events_data).expect("failed to poll events");

    for data_buf in events_data.iter_mut().take(event_stats.read) {
        // You must ensure that the definition of the struct (here `EventData`) is the same
        // in the userspace and in the bpf program.
        let ptr = data_buf.as_ptr() as *const EventData;
        let data: EventData = unsafe { ptr.read_unaligned() };

        assert_eq!(data.cpu_id, CPU_ID, "unexpected data: {:?}", data);
        assert_eq!(data.tag, 0xAB, "unexpected data: {:?}", data);
    }
}
