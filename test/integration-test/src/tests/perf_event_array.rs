use aya::{
    EbpfLoader,
    maps::{
        PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::{
        UProbe,
        perf_event::{PerfEventConfig, PerfEventGroup, PerfEventScope, SoftwareEvent},
        uprobe::UProbeScope,
    },
    util::online_cpus,
};
use rstest::rstest;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_emit_event() {
    std::hint::black_box(());
}

#[rstest]
#[case::legacy(crate::PERF_EVENT_ARRAY, "EVENTS_LEGACY", "emit_event_legacy")]
#[case::btf(crate::PERF_EVENT_ARRAY, "EVENTS", "emit_event")]
#[case::byte_legacy(crate::PERF_EVENT_BYTE_ARRAY, "EVENTS_LEGACY", "emit_event_legacy")]
#[case::byte_btf(crate::PERF_EVENT_BYTE_ARRAY, "EVENTS", "emit_event")]
#[test_attr(test_log::test)]
fn emit_event(#[case] bpf_obj: &[u8], #[case] events_map: &str, #[case] prog: &str) {
    let mut bpf = EbpfLoader::new()
        .load(bpf_obj)
        .expect("load perf event array program");

    let mut perf = PerfEventArray::try_from(bpf.take_map(events_map).unwrap()).unwrap();
    let cpus = online_cpus().map_err(|(_, error)| error).unwrap();
    let mut buffers: Vec<_> = cpus
        .into_iter()
        .map(|cpu| {
            let buffer = PerfEventArrayBuffer::open(cpu, 2).unwrap();
            perf.set(cpu, &buffer).unwrap();
            buffer
        })
        .collect();

    let uprobe: &mut UProbe = bpf
        .program_mut(prog)
        .unwrap_or_else(|| panic!("missing program {prog}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog} is not a uprobe: {err}"));
    uprobe
        .load()
        .unwrap_or_else(|err| panic!("load {prog}: {err}"));
    uprobe
        .attach(
            ["trigger_emit_event"],
            "/proc/self/exe",
            UProbeScope::AllProcesses,
        )
        .unwrap_or_else(|err| panic!("attach {prog}: {err}"));

    trigger_emit_event();

    let mut payloads = Vec::new();
    for buf in &mut buffers {
        buf.for_each(|event| match event {
            PerfEvent::Sample { head, .. } => {
                payloads.push(u64::from_ne_bytes(
                    head[..size_of::<u64>()].try_into().unwrap(),
                ));
            }
            PerfEvent::Lost { count } => panic!("kernel dropped {count} samples"),
        });
    }
    assert_eq!(payloads, [0xDEAD_BEEFu64]);
}

#[test_log::test]
fn read_counter() {
    let mut bpf = EbpfLoader::new()
        .load(crate::PERF_EVENT_ARRAY)
        .expect("load perf event array program");

    let mut output = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap()).unwrap();
    let mut output_buffers: Vec<_> = online_cpus()
        .map_err(|(_, error)| error)
        .unwrap()
        .into_iter()
        .map(|cpu| {
            let buffer = PerfEventArrayBuffer::open(cpu, 2).unwrap();
            output.set(cpu, &buffer).unwrap();
            buffer
        })
        .collect();

    let mut group = PerfEventGroup::open(
        PerfEventConfig::Software(SoftwareEvent::TaskClock),
        [PerfEventConfig::Software(SoftwareEvent::CpuClock)],
        PerfEventScope::CallingProcess { cpu: None },
    )
    .unwrap();
    let mut counters = PerfEventArray::try_from(bpf.take_map("COUNTERS").unwrap()).unwrap();
    for (index, event) in (0u32..).zip(group.events()) {
        counters.set(index, &event).unwrap();
    }

    let uprobe: &mut UProbe = bpf.program_mut("read_counter").unwrap().try_into().unwrap();
    uprobe.load().unwrap();
    uprobe
        .attach(
            ["trigger_emit_event"],
            "/proc/self/exe",
            UProbeScope::AllProcesses,
        )
        .unwrap();

    group.enable().unwrap();
    trigger_emit_event();
    group.disable().unwrap();
    for index in 0..2 {
        counters.unset(index).unwrap();
    }

    let group_read = group.read().unwrap();
    assert_eq!(group_read.values.len(), 2);
    assert!(group_read.values.iter().all(|value| *value > 0));
    assert!(group_read.time_enabled > 0);
    assert!(group_read.time_running > 0);

    let mut readings = Vec::new();
    for buffer in &mut output_buffers {
        buffer.for_each(|event| match event {
            PerfEvent::Sample { head, .. } => {
                let (fields, _) = head.as_chunks::<8>();
                let fields: Vec<_> = fields
                    .iter()
                    .take(6)
                    .map(|field| u64::from_ne_bytes(*field))
                    .collect();
                readings.push(fields);
            }
            PerfEvent::Lost { count } => panic!("kernel dropped {count} samples"),
        });
    }

    let [reading] = readings.as_slice() else {
        panic!("expected one counter reading, got {readings:?}");
    };
    let [
        task_clock,
        task_enabled,
        task_running,
        cpu_clock,
        cpu_enabled,
        cpu_running,
    ] = reading.as_slice()
    else {
        panic!("expected two counter readings, got {reading:?}");
    };
    assert!(*task_clock > 0);
    assert!(*task_enabled > 0);
    assert!(*task_running > 0);
    assert!(*cpu_clock > 0);
    assert!(*cpu_enabled > 0);
    assert!(*cpu_running > 0);
}
