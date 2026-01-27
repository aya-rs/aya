use aya::{
    EbpfLoader,
    maps::{Array, MapType},
    programs::UProbe,
    sys::is_map_supported,
};
use integration_common::bloom_filter::{
    CONTAINS_ABSENT_INDEX, CONTAINS_PRESENT_INDEX, INSERT_INDEX,
};
use libc::c_long;

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
    if !is_map_supported(MapType::BloomFilter).unwrap() {
        eprintln!("skipping test - bloom filter map not supported");
        return;
    }

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

    let array = Array::<_, c_long>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    const PRESENT: u32 = 1337;
    const ABSENT: u32 = 1337_1337;

    trigger_bloom_insert(INSERT_INDEX, PRESENT);
    assert_eq!(array.get(&INSERT_INDEX, 0).unwrap(), 0);

    trigger_bloom_contains(CONTAINS_PRESENT_INDEX, PRESENT);
    assert_eq!(array.get(&CONTAINS_PRESENT_INDEX, 0).unwrap(), 0);

    trigger_bloom_contains(CONTAINS_ABSENT_INDEX, ABSENT);
    let absent_status = array.get(&CONTAINS_ABSENT_INDEX, 0).unwrap();
    // Bloom filters can yield false positives; treat both a miss (-ENOENT) and a hit (0) as valid.
    assert!(
        absent_status == -c_long::from(libc::ENOENT) || absent_status == 0,
        "unexpected BloomFilter result for absent value: {absent_status}"
    );
}
