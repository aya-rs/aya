use aya::{
    EbpfLoader,
    maps::{PerfEventArray, perf::Events},
    programs::{UProbe, uprobe::UProbeScope},
    util::online_cpus,
};
use bytes::BytesMut;
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_emit_event() {
    std::hint::black_box(());
}

#[test_case(crate::PERF_EVENT_ARRAY, "EVENTS_LEGACY", "emit_event_legacy" ; "legacy")]
#[test_case(crate::PERF_EVENT_ARRAY, "EVENTS", "emit_event" ; "btf")]
#[test_case(crate::PERF_EVENT_BYTE_ARRAY, "EVENTS_LEGACY", "emit_event_legacy" ; "byte_legacy")]
#[test_case(crate::PERF_EVENT_BYTE_ARRAY, "EVENTS", "emit_event" ; "byte_btf")]
#[test_log::test]
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

    // perf raw record: [u32 size, payload, pad].
    const SAMPLE_SIZE: usize =
        (size_of::<u32>() + size_of::<u64>()).next_multiple_of(8) - size_of::<u32>();

    let mut total_read = 0;
    let mut payload = 0u64;
    for buf in &mut buffers {
        let mut out = [BytesMut::from(&[0xAAu8; SAMPLE_SIZE][..])];
        let Events { read, lost } = buf.read_events(&mut out).unwrap();
        assert_eq!(lost, 0);
        total_read += read;
        for out in &out[..read] {
            assert_eq!(out.len(), SAMPLE_SIZE);
            payload = u64::from_ne_bytes(out[..size_of::<u64>()].try_into().unwrap());
        }
    }

    assert_eq!(total_read, 1);
    assert_eq!(payload, 0xDEAD_BEEF);
}
