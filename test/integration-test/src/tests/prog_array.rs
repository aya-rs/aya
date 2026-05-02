use aya::{
    EbpfLoader,
    maps::{Array, MapType, ProgramArray},
    programs::{UProbe, uprobe::UProbeScope},
    sys::is_map_supported,
};
use integration_common::prog_array::{
    FAILURE_SENTINEL, RESULT_INDEX, SUCCESS_INDEX, SUCCESS_SENTINEL,
};
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_tail_call_empty() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_tail_call_success() {
    std::hint::black_box(());
}

#[test_case(
    "RESULT_LEGACY",
    "tail_call_empty_legacy"
    ; "legacy"
)]
#[test_case(
    "RESULT",
    "tail_call_empty"
    ; "btf"
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
    prog.attach(
        "trigger_tail_call_empty",
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap_or_else(|err| panic!("attach {entry_prog}: {err}"));

    let result = Array::<_, u32>::try_from(bpf.map(result_map).unwrap()).unwrap();

    trigger_tail_call_empty();

    assert_eq!(
        result.get(&RESULT_INDEX, 0).unwrap(),
        FAILURE_SENTINEL,
        "tail_call on an empty slot must fall through and let the probe record the sentinel",
    );
}

#[test_case(
    "RESULT_LEGACY",
    "ARRAY_LEGACY",
    "tail_call_empty_legacy",
    "tail_call_target_legacy"
    ; "legacy"
)]
#[test_case(
    "RESULT",
    "ARRAY",
    "tail_call_empty",
    "tail_call_target"
    ; "btf"
)]
#[test_log::test]
fn tail_call_success(result_map: &str, array_map: &str, entry_prog: &str, target_prog: &str) {
    if !is_map_supported(MapType::ProgramArray).unwrap() {
        eprintln!("skipping test - program array map not supported");
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::PROG_ARRAY)
        .expect("load prog_array program");

    {
        let target: &mut UProbe = bpf
            .program_mut(target_prog)
            .unwrap_or_else(|| panic!("missing program {target_prog}"))
            .try_into()
            .unwrap_or_else(|err| panic!("program {target_prog} is not a uprobe: {err}"));
        target
            .load()
            .unwrap_or_else(|err| panic!("load {target_prog}: {err}"));
    }

    {
        let entry: &mut UProbe = bpf
            .program_mut(entry_prog)
            .unwrap_or_else(|| panic!("missing program {entry_prog}"))
            .try_into()
            .unwrap_or_else(|err| panic!("program {entry_prog} is not a uprobe: {err}"));
        entry
            .load()
            .unwrap_or_else(|err| panic!("load {entry_prog}: {err}"));
        entry
            .attach(
                "trigger_tail_call_success",
                "/proc/self/exe",
                UProbeScope::AllProcesses,
            )
            .unwrap_or_else(|err| panic!("attach {entry_prog}: {err}"));
    }

    let mut array: ProgramArray<_> = bpf.take_map(array_map).unwrap().try_into().unwrap();
    let target_fd = bpf.program(target_prog).unwrap().fd().unwrap();
    array.set(0, target_fd, 0).unwrap();

    let result = Array::<_, u32>::try_from(bpf.map(result_map).unwrap()).unwrap();

    trigger_tail_call_success();

    assert_eq!(
        result.get(&SUCCESS_INDEX, 0).unwrap(),
        SUCCESS_SENTINEL,
        "tail_call into a populated slot must jump to the target program",
    );
    assert_eq!(
        result.get(&RESULT_INDEX, 0).unwrap(),
        0,
        "entry must not reach the failure path after a successful tail_call",
    );
}
