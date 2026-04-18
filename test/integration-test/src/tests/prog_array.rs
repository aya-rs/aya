use aya::{
    EbpfLoader,
    maps::{Array, MapType},
    programs::UProbe,
    sys::is_map_supported,
};
use integration_common::prog_array::{FAILURE_SENTINEL, RESULT_INDEX};
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_tail_call_empty() {
    std::hint::black_box(());
}

#[test_case(
    "RESULT_LEGACY",
    "tail_call_empty_legacy"
    ; "legacy"
)]
#[test_log::test]
fn tail_call_empty(result_map: &str, entry_prog: &str) {
    if !is_map_supported(MapType::ProgramArray).unwrap() {
        eprintln!("skipping test - program array map not supported");
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::PROG_ARRAY)
        .expect("load prog_array program");

    let prog: &mut UProbe = bpf
        .program_mut(entry_prog)
        .unwrap_or_else(|| panic!("missing program {entry_prog}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {entry_prog} is not a uprobe: {err}"));
    prog.load()
        .unwrap_or_else(|err| panic!("load {entry_prog}: {err}"));
    prog.attach("trigger_tail_call_empty", "/proc/self/exe", None)
        .unwrap_or_else(|err| panic!("attach {entry_prog}: {err}"));

    let result = Array::<_, u32>::try_from(bpf.map(result_map).unwrap()).unwrap();

    trigger_tail_call_empty();

    assert_eq!(
        result.get(&RESULT_INDEX, 0).unwrap(),
        FAILURE_SENTINEL,
        "tail_call on an empty slot must fall through and let the probe record the sentinel",
    );
}
