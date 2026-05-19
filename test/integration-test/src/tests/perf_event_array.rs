use aya::{
    EbpfLoader,
    maps::{PerfEventArray, perf::PerfEvent},
    programs::{UProbe, uprobe::UProbeScope},
    util::online_cpus,
};
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_emit_event() {
    std::hint::black_box(());
}

#[test_log::test(test_case(crate::PERF_EVENT_ARRAY, "EVENTS_LEGACY", "emit_event_legacy" ; "legacy"))]
#[test_case(crate::PERF_EVENT_ARRAY, "EVENTS", "emit_event" ; "btf")]
#[test_case(crate::PERF_EVENT_BYTE_ARRAY, "EVENTS_LEGACY", "emit_event_legacy" ; "byte_legacy")]
#[test_case(crate::PERF_EVENT_BYTE_ARRAY, "EVENTS", "emit_event" ; "byte_btf")]
fn emit_event(bpf_obj: &[u8], events_map: &str, prog: &str) {
    let mut bpf = EbpfLoader::new()
        .load(bpf_obj)
        .expect("load perf event array program");

    let mut perf = PerfEventArray::try_from(bpf.take_map(events_map).unwrap()).unwrap();
    let cpus = online_cpus().map_err(|(_, error)| error).unwrap();
    let mut buffers: Vec<_> = cpus
        .into_iter()
        .map(|cpu| perf.open(cpu, None).unwrap())
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
            "trigger_emit_event",
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
