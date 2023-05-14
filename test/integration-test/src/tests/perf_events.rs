use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use aya::maps::{AsyncPerfEventArray, PerfEventArray};
use aya::programs::perf_event::{perf_event_open, PerfEventLinkId, PerfEventScope};
use aya::programs::{PerfEvent, PerfTypeId, ProgramError, SamplePolicy};
use aya::Bpf;
use aya_obj::generated::{perf_hw_id, perf_sw_ids, perf_type_id};
use bytes::BytesMut;
use test_log::test;

/// Data sent by the bpf program to userspace.
/// This structure must be defined in the exact same way on the bpf side.
#[derive(Debug)]
#[repr(C)]
struct EventData {
    value: u64,
    cpu_id: u32,
    tag: u8,
}

const CPU_ID: u32 = 0;
const SAMPLING_FREQUENCY_HZ: u64 = 10;
const BUF_PAGE_COUNT: usize = 2;
const WAIT_TIMEOUT: Duration = Duration::from_secs(1);

/// Opens an hardware perf_event for testing.
// Beware: this returns an `OwnedFd`, which means that the file descriptor is closed on drop.
fn open_perf_event_hw() -> Result<OwnedFd, ProgramError> {
    perf_event_open(
        perf_type_id::PERF_TYPE_HARDWARE as u32,
        perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64,
        PerfEventScope::AllProcessesOneCpu { cpu: CPU_ID },
        None,
        None,
        0,
    )
}

/// Attaches a PerfEvent bpf program to a software clock event.
fn attach_bpf_to_clock(program: &mut PerfEvent) -> Result<PerfEventLinkId, ProgramError> {
    program.attach(
        PerfTypeId::Software,
        perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
        PerfEventScope::AllProcessesOneCpu { cpu: CPU_ID },
        SamplePolicy::Frequency(SAMPLING_FREQUENCY_HZ),
    )
}

#[test]
fn perf_event_read_from_kernel() {
    // load bpf program
    let mut bpf = Bpf::load(crate::PERF_EVENTS).expect("failed to load bpf code");
    let mut descriptors = PerfEventArray::try_from(bpf.take_map("DESCRIPTORS").unwrap()).unwrap();
    let mut bpf_output = PerfEventArray::try_from(bpf.take_map("OUTPUT").unwrap()).unwrap();

    // open a perf_event
    let event_fd = open_perf_event_hw().unwrap();

    // pass pointer to bpf array
    descriptors
        .set(0, &event_fd)
        .expect("failed to put event's fd into the map");

    // load program
    let program: &mut PerfEvent = bpf
        .program_mut("on_perf_event")
        .unwrap()
        .try_into()
        .unwrap();

    program
        .load()
        .expect("the bpf program should load properly");

    // get buffer to poll the events
    let mut buf = bpf_output
        .open(CPU_ID, Some(BUF_PAGE_COUNT))
        .expect("failed to open output buffer to poll events");

    // attach program
    attach_bpf_to_clock(program).expect("the bpf program should attach properly");

    // wait for the values to be added to the buffer
    let t0 = Instant::now();
    while !buf.readable() {
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            t0.elapsed() < WAIT_TIMEOUT,
            "timeout elapsed: no data in the buffer"
        );
    }

    // read the events and check that the returned data is correct
    let mut events_data: [BytesMut; BUF_PAGE_COUNT] = std::array::from_fn(|_| BytesMut::new());
    let events_stats = buf
        .read_events(&mut events_data)
        .expect("failed to poll events");

    for data_buf in events_data.iter_mut().take(events_stats.read) {
        let ptr = data_buf.as_ptr() as *const EventData;
        let data: EventData = unsafe { ptr.read_unaligned() };

        assert_eq!(data.cpu_id, CPU_ID, "unexpected data: {:?}", data);
        assert_eq!(data.tag, 0xAB, "unexpected data: {:?}", data);
    }
}

#[test(tokio::test)]
async fn perf_event_read_from_kernel_async() {
    // load bpf program
    let mut bpf = Bpf::load(crate::PERF_EVENTS).expect("failed to load bpf code");
    let mut descriptors =
        AsyncPerfEventArray::try_from(bpf.take_map("DESCRIPTORS").unwrap()).unwrap();
    let mut bpf_output = AsyncPerfEventArray::try_from(bpf.take_map("OUTPUT").unwrap()).unwrap();

    // open a perf_event
    let event_fd = open_perf_event_hw().unwrap();

    // pass pointer to bpf array
    descriptors
        .set(0, &event_fd)
        .expect("failed to put event's fd into the map");

    // load program
    let program: &mut PerfEvent = bpf
        .program_mut("on_perf_event")
        .unwrap()
        .try_into()
        .unwrap();

    program
        .load()
        .expect("the bpf program should load properly");

    // get buffer to poll the events
    let mut buf = bpf_output
        .open(CPU_ID, Some(BUF_PAGE_COUNT))
        .expect("failed to open output buffer to poll events");

    // attach program
    attach_bpf_to_clock(program).expect("the bpf program should attach properly");

    // read the events as soon as they are available
    let mut events_data: [BytesMut; BUF_PAGE_COUNT] = std::array::from_fn(|_| BytesMut::new());
    let events_stats = tokio::time::timeout(WAIT_TIMEOUT, buf.read_events(&mut events_data))
        .await
        .expect("timeout elapsed: no data in the buffer")
        .expect("failed to poll events");

    // check that the returned data is correct
    for data_buf in events_data.iter_mut().take(events_stats.read) {
        let ptr = data_buf.as_ptr() as *const EventData;
        let data: EventData = unsafe { ptr.read_unaligned() };

        assert_eq!(data.cpu_id, CPU_ID, "unexpected data: {:?}", data);
        assert_eq!(data.tag, 0xAB, "unexpected data: {:?}", data);
    }
}
