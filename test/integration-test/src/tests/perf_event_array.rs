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

    // bpf_perf_event_output pads the raw record to 8-byte alignment; an 8-byte
    // u64 payload occupies size_of::<u64>() + 4 bytes in the perf buffer.
    const SAMPLE_SIZE: usize = size_of::<u64>() + 4;

    let mut total_read = 0;
    let mut payload = 0u64;
    for buf in &mut buffers {
        let mut out = [BytesMut::from(&[0xAAu8; SAMPLE_SIZE + 4][..])];
        let tail = out[0].split_off(SAMPLE_SIZE);
        let Events { read, lost } = buf.read_events(&mut out).unwrap();
        assert_eq!(lost, 0);
        if read > 0 {
            total_read += read;
            assert_eq!(out[0].len(), SAMPLE_SIZE);
            payload = u64::from_ne_bytes(out[0][..size_of::<u64>()].try_into().unwrap());
            assert!(
                tail.iter().all(|&b| b == 0xAA),
                "bytes beyond payload were overwritten",
            );
        }
    }

    assert_eq!(total_read, 1);
    assert_eq!(payload, 0xDEAD_BEEF);
}
