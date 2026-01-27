use aya::{EbpfLoader, maps::Array, programs::UProbe};
use integration_common::bloom_filter::{
    CONTAINS_ABSENT_INDEX, CONTAINS_PRESENT_INDEX, INSERT_INDEX,
};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bloom_insert(result_index: u32, value: u32) {
    core::hint::black_box(result_index);
    core::hint::black_box(value);
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_bloom_contains(result_index: u32, value: u32) {
    core::hint::black_box(result_index);
    core::hint::black_box(value);
}

#[test_log::test]
fn bloom_filter_basic() {
    let mut bpf = EbpfLoader::new()
        .load(crate::BLOOM_FILTER)
        .expect("load bloom_filter program");

    for (prog_name, symbol) in [
        ("bloom_filter_insert", "trigger_bloom_insert"),
        ("bloom_filter_contains", "trigger_bloom_contains"),
    ] {
        let prog: &mut UProbe = bpf
            .program_mut(prog_name)
            .unwrap_or_else(|| panic!("missing program {prog_name}"))
            .try_into()
            .unwrap_or_else(|_| panic!("program {prog_name} is not a uprobe"));
        prog.load()
            .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
        prog.attach(symbol, "/proc/self/exe", None)
            .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));
    }

    let array = Array::<_, i64>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    const PRESENT: u32 = 0xdead_beef;
    const ABSENT: u32 = 0xface_cafe;

    trigger_bloom_insert(INSERT_INDEX, PRESENT);
    assert_eq!(array.get(&INSERT_INDEX, 0).unwrap(), 0);

    trigger_bloom_contains(CONTAINS_PRESENT_INDEX, PRESENT);
    assert_eq!(array.get(&CONTAINS_PRESENT_INDEX, 0).unwrap(), 0);

    trigger_bloom_contains(CONTAINS_ABSENT_INDEX, ABSENT);
    assert_eq!(
        array.get(&CONTAINS_ABSENT_INDEX, 0).unwrap(),
        -i64::from(libc::ENOENT)
    );
}
