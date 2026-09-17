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
        .iter()
        .map(|cpu| PerfEventArrayBuffer::open(*cpu, 2).unwrap())
        .collect();
    for (cpu, buffer) in cpus.into_iter().zip(&buffers) {
        perf.set(cpu, buffer).unwrap();
    }

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
    let cpus = online_cpus().map_err(|(_, error)| error).unwrap();
    let mut output_buffers: Vec<_> = cpus
        .iter()
        .map(|cpu| PerfEventArrayBuffer::open(*cpu, 2).unwrap())
        .collect();
    for (cpu, buffer) in cpus.into_iter().zip(&output_buffers) {
        output.set(cpu, buffer).unwrap();
    }

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

    let read_ebpf_counters = |buffers: &mut [PerfEventArrayBuffer]| {
        let mut readings = Vec::new();
        for buffer in buffers {
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
        [
            *task_clock,
            *task_enabled,
            *task_running,
            *cpu_clock,
            *cpu_enabled,
            *cpu_running,
        ]
    };
    let run_workload = || {
        for value in 0..1_000_000 {
            std::hint::black_box(value);
        }
    };

    // Enable the group, exercise it, and disable it.
    group.enable().unwrap();
    run_workload();
    group.disable().unwrap();

    // read from userspace
    let disabled_read = group.read().unwrap();
    assert_eq!(disabled_read.values.len(), 2);
    assert!(disabled_read.values.iter().all(|value| *value > 0));
    assert!(disabled_read.time_enabled > 0);
    assert!(disabled_read.time_running > 0);
    let disabled_values: [u64; 2] = disabled_read.values.try_into().unwrap();
    let disabled_time_enabled = disabled_read.time_enabled;
    let disabled_time_running = disabled_read.time_running;

    // read from ebpf
    trigger_emit_event();
    let disabled_ebpf_read = read_ebpf_counters(&mut output_buffers);
    assert!(disabled_ebpf_read.iter().all(|value| *value > 0));

    // run again with the group disabled, counters shouldn't move
    run_workload();
    trigger_emit_event();
    let disabled_ebpf_read_after_workload = read_ebpf_counters(&mut output_buffers);
    assert_eq!(disabled_ebpf_read_after_workload, disabled_ebpf_read);

    let disabled_read = group.read().unwrap();
    assert_eq!(disabled_read.values, disabled_values);
    assert_eq!(disabled_read.time_enabled, disabled_time_enabled);
    assert_eq!(disabled_read.time_running, disabled_time_running);

    // enabling resumes event collection
    group.enable().unwrap();
    run_workload();
    trigger_emit_event();
    group.disable().unwrap();
    let resumed_ebpf_read = read_ebpf_counters(&mut output_buffers);
    assert!(
        resumed_ebpf_read
            .iter()
            .zip(disabled_ebpf_read)
            .all(|(resumed, disabled)| *resumed > disabled),
        "event collection didn't resume after enabling the perf group"
    );

    let resumed_read = group.read().unwrap();
    assert!(
        resumed_read
            .values
            .iter()
            .zip(&disabled_values)
            .all(|(resumed, disabled)| resumed > disabled),
        "event collection didn't resume after enabling the perf group"
    );
    assert!(resumed_read.time_enabled > disabled_time_enabled);
    assert!(resumed_read.time_running > disabled_time_running);
    let resumed_time_enabled = resumed_read.time_enabled;
    let resumed_time_running = resumed_read.time_running;

    for index in 0..2 {
        counters.unset(index).unwrap();
    }
    group.reset().unwrap();
    let reset_read = group.read().unwrap();
    assert!(reset_read.values.iter().all(|value| *value == 0));
    assert_eq!(reset_read.time_enabled, resumed_time_enabled);
    assert_eq!(reset_read.time_running, resumed_time_running);
}
