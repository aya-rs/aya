use aya::{
    EbpfLoader,
    maps::{Array, MapError, MapType, bloom_filter::BloomFilter},
    programs::UProbe,
    sys::is_map_supported,
};
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

    let array = Array::<_, i32>::try_from(bpf.take_map("RESULT").unwrap()).unwrap();
    let mut filter = BloomFilter::<_, u32>::try_from(bpf.take_map("FILTER").unwrap()).unwrap();
    const PRESENT: u32 = 1337;
    const ABSENT: u32 = 1337_1337;
    const USER_PRESENT: u32 = 42_4242;
    const USER_ABSENT: u32 = 7_777_777;

    trigger_bloom_insert(INSERT_INDEX, PRESENT);
    assert_eq!(array.get(&INSERT_INDEX, 0).unwrap(), 0);

    trigger_bloom_contains(CONTAINS_PRESENT_INDEX, PRESENT);
    assert_eq!(array.get(&CONTAINS_PRESENT_INDEX, 0).unwrap(), 0);

    trigger_bloom_contains(CONTAINS_ABSENT_INDEX, ABSENT);
    let absent_status = array.get(&CONTAINS_ABSENT_INDEX, 0).unwrap();
    // Bloom filters can yield false positives; treat both a miss (-ENOENT) and a hit (0) as valid.
    assert!(
        absent_status == -libc::ENOENT || absent_status == 0,
        "unexpected BloomFilter result for absent value: {absent_status}"
    );

    let mut present_query = PRESENT;
    filter
        .contains(&mut present_query, 0)
        .expect("user-space contains sees eBPF insert");

    let mut user_absent = USER_ABSENT;
    match filter.contains(&mut user_absent, 0) {
        Ok(()) | Err(MapError::ElementNotFound) => {}
        Err(err) => panic!("unexpected BloomFilter::contains result for absent value: {err}"),
    }

    filter.insert(USER_PRESENT, 0).unwrap();
    let mut user_present = USER_PRESENT;
    filter.contains(&mut user_present, 0).unwrap();

    trigger_bloom_contains(CONTAINS_PRESENT_INDEX, USER_PRESENT);
    assert_eq!(array.get(&CONTAINS_PRESENT_INDEX, 0).unwrap(), 0);
}
