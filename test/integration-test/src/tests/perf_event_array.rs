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

    // PERF_SAMPLE_RAW is encoded as `u32 size + data`; the kernel rounds the
    // field's total to 8 bytes. `read_events` copies `size` bytes (payload + pad).
    const PADDED_SAMPLE_SIZE: usize = {
        let size_field = size_of::<u32>();
        (size_field + size_of::<u64>()).next_multiple_of(8) - size_field
    };

    let mut payloads = Vec::new();
    for buf in &mut buffers {
        let mut out = [BytesMut::from(&[0xAAu8; PADDED_SAMPLE_SIZE * 2][..])];
        let tail = out[0].split_off(PADDED_SAMPLE_SIZE);
        let Events { read, lost } = buf.read_events(&mut out).unwrap();
        assert_eq!(lost, 0);
        assert!(
            tail.iter().all(|&b| b == 0xAA),
            "bytes beyond payload were overwritten",
        );
        for sample in &out[..read] {
            assert_eq!(sample.len(), PADDED_SAMPLE_SIZE);
            payloads.push(u64::from_ne_bytes(
                sample[..size_of::<u64>()].try_into().unwrap(),
            ));
        }
    }
    assert_eq!(payloads, [0xDEAD_BEEFu64]);
}
