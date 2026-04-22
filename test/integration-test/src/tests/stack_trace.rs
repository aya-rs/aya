use aya::{
    EbpfLoader,
    maps::{Array, MapType, StackTraceMap},
    programs::UProbe,
    sys::is_map_supported,
};
use integration_common::stack_trace::TestResult;
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_record_stackid() {
    std::hint::black_box(());
}

#[test_case("STACKS_LEGACY", "RESULT_LEGACY", "record_stackid_legacy" ; "legacy")]
#[test_case("STACKS", "RESULT", "record_stackid" ; "btf")]
#[test_log::test]
fn record_stackid(stacks_map: &str, result_map: &str, prog: &str) {
    if !is_map_supported(MapType::StackTrace).unwrap() {
        eprintln!("skipping test - stack trace map not supported");
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::STACK_TRACE)
        .expect("load stack_trace program");

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
            "trigger_record_stackid",
            "/proc/self/exe",
            aya::programs::uprobe::UProbeScope::AllProcesses,
        )
        .unwrap_or_else(|err| panic!("attach {prog}: {err}"));

    trigger_record_stackid();

    let result = Array::<_, TestResult>::try_from(bpf.map(result_map).unwrap()).unwrap();
    let TestResult { stack_id, ran } = result.get(&0, 0).unwrap();
    assert!(ran, "probe {prog} did not run");

    let stacks = StackTraceMap::try_from(bpf.map(stacks_map).unwrap()).unwrap();
    let trace = stacks
        .get(&stack_id, 0)
        .expect("stack_id not found in stack trace map");
    let frames = trace.frames();
    assert!(
        frames.iter().any(|f| f.ip != 0),
        "stack trace for stack_id {stack_id} has no non-zero IP frame; got {} frames",
        frames.len(),
    );
}
