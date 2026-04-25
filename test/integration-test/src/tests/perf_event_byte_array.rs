use aya::{
    EbpfLoader,
    maps::PerfEventArray,
    programs::{UProbe, uprobe::UProbeScope},
    util::online_cpus,
};
use bytes::BytesMut;
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_emit_event_bytes() {
    std::hint::black_box(());
}

#[test_case("EVENTS_LEGACY", "emit_event_legacy" ; "legacy")]
#[test_case("EVENTS", "emit_event" ; "btf")]
#[test_log::test]
fn emit_event(events_map: &str, prog: &str) {
    let mut bpf = EbpfLoader::new()
        .load(crate::PERF_EVENT_BYTE_ARRAY)
        .expect("load perf_event_byte_array program");

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
            "trigger_emit_event_bytes",
            "/proc/self/exe",
            UProbeScope::AllProcesses,
        )
        .unwrap_or_else(|err| panic!("attach {prog}: {err}"));

    trigger_emit_event_bytes();

    let mut total_read = 0;
    let mut payload = 0u64;
    for buf in &mut buffers {
        let mut out = [BytesMut::with_capacity(16)];
        let events = buf.read_events(&mut out).unwrap();
        if events.read > 0 {
            total_read += events.read;
            payload = u64::from_ne_bytes(out[0][..8].try_into().unwrap());
        }
    }

    assert_eq!(total_read, 1, "expected 1 event from {prog}");
    assert_eq!(payload, 0xDEAD_BEEF, "wrong payload from {prog}");
}
