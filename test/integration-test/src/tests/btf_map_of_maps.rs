use aya::{
    Ebpf,
    maps::{Array, ArrayOfMaps, CreatableMap, HashOfMaps, MapData},
    programs::UProbe,
};

/// Loads and attaches a uprobe from the BTF map-of-maps test binary.
///
/// The program name is `test_{name}` and the trigger symbol is `trigger_{name}`.
fn load_and_attach(ebpf: &mut Ebpf, name: &str) {
    let prog: &mut UProbe = ebpf
        .program_mut(&format!("test_{name}"))
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(format!("trigger_{name}").as_str(), "/proc/self/exe", None)
        .unwrap();
}

/// Reads `RESULTS[index]` and asserts `value` and `ran == 1`.
fn assert_result(ebpf: &Ebpf, index: u32, expected_value: u32) {
    let results: Array<&MapData, integration_common::btf_map_of_maps::TestResult> =
        ebpf.map("RESULTS").unwrap().try_into().unwrap();
    let result = results.get(&index, 0).unwrap();
    assert_eq!(result.value, expected_value, "RESULTS[{index}].value");
    assert_eq!(result.ran, 1, "RESULTS[{index}].ran");
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_btf_array_of_maps() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_btf_hash_of_maps() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_btf_array_of_maps_get_value() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_btf_hash_of_maps_get_value() {
    std::hint::black_box(());
}

/// Test BTF `ArrayOfMaps`: insert inner maps and verify eBPF can read them.
#[test_log::test]
fn btf_array_of_maps() {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner_array: Array<MapData, u32> = Array::create(10, 0).unwrap();
    inner_array.set(0, 42u32, 0).unwrap();

    {
        let mut outer: ArrayOfMaps<&mut MapData, Array<MapData, u32>> =
            ebpf.map_mut("ARRAY_OF_MAPS").unwrap().try_into().unwrap();
        outer.set(0, &inner_array, 0).unwrap();
    }

    load_and_attach(&mut ebpf, "btf_array_of_maps");
    trigger_btf_array_of_maps();
    assert_result(&ebpf, 0, 42);
}

/// Test BTF `HashOfMaps`: insert inner maps and verify eBPF can read them.
#[test_log::test]
fn btf_hash_of_maps() {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner_array: Array<MapData, u32> = Array::create(10, 0).unwrap();
    inner_array.set(0, 55u32, 0).unwrap();

    {
        let mut outer: HashOfMaps<&mut MapData, u32, Array<MapData, u32>> =
            ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
        outer.insert(0u32, &inner_array, 0).unwrap();
    }

    load_and_attach(&mut ebpf, "btf_hash_of_maps");
    trigger_btf_hash_of_maps();
    assert_result(&ebpf, 1, 55);
}

/// Test BTF `ArrayOfMaps::get_value` and `get_value_ptr_mut`.
#[test_log::test]
fn btf_array_of_maps_get_value() {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner_1: Array<MapData, u32> = Array::create(10, 0).unwrap();
    inner_1.set(0, 77u32, 0).unwrap();

    let mut inner_2: Array<MapData, u32> = Array::create(10, 0).unwrap();
    inner_2.set(0, 0u32, 0).unwrap();

    {
        let mut outer: ArrayOfMaps<&mut MapData, Array<MapData, u32>> =
            ebpf.map_mut("ARRAY_OF_MAPS").unwrap().try_into().unwrap();
        outer.set(0, &inner_1, 0).unwrap();
        outer.set(1, &inner_2, 0).unwrap();
    }

    load_and_attach(&mut ebpf, "btf_array_of_maps_get_value");
    trigger_btf_array_of_maps_get_value();

    // get_value should have read inner_1[0] == 77.
    assert_result(&ebpf, 2, 77);

    // get_value_ptr_mut should have written 99 to inner_2[0].
    assert_eq!(inner_2.get(&0, 0).unwrap(), 99);
}

/// Test BTF `HashOfMaps::get_value` and `get_value_ptr_mut`.
#[test_log::test]
fn btf_hash_of_maps_get_value() {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner_1: Array<MapData, u32> = Array::create(10, 0).unwrap();
    inner_1.set(0, 55u32, 0).unwrap();

    let mut inner_2: Array<MapData, u32> = Array::create(10, 0).unwrap();
    inner_2.set(0, 0u32, 0).unwrap();

    {
        let mut outer: HashOfMaps<&mut MapData, u32, Array<MapData, u32>> =
            ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
        outer.insert(0u32, &inner_1, 0).unwrap();
        outer.insert(1u32, &inner_2, 0).unwrap();
    }

    load_and_attach(&mut ebpf, "btf_hash_of_maps_get_value");
    trigger_btf_hash_of_maps_get_value();

    // get_value should have read inner_1[0] == 55.
    assert_result(&ebpf, 3, 55);

    // get_value_ptr_mut should have written 88 to inner_2[0].
    assert_eq!(inner_2.get(&0, 0).unwrap(), 88);
}

/// Test dynamic inner map creation with `HashOfMaps`.
#[test_log::test]
fn btf_hash_of_maps_dynamic() {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    // Create inner maps dynamically matching the BTF inner definition (Array<u32, 10>).
    let mut inner_1: Array<MapData, u32> = Array::create(10, 0).unwrap();
    let mut inner_2: Array<MapData, u32> = Array::create(10, 0).unwrap();

    inner_1.set(0, 1000u32, 0).unwrap();
    inner_2.set(0, 2000u32, 0).unwrap();

    {
        let mut outer: HashOfMaps<&mut MapData, u32, Array<MapData, u32>> =
            ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
        outer.insert(10u32, &inner_1, 0).unwrap();
        outer.insert(11u32, &inner_2, 0).unwrap();
    }

    // Verify data persists after insertion into the outer map.
    assert_eq!(inner_1.get(&0, 0).unwrap(), 1000);
    assert_eq!(inner_2.get(&0, 0).unwrap(), 2000);

    // Modify and verify changes persist.
    inner_1.set(1, 3000u32, 0).unwrap();
    assert_eq!(inner_1.get(&1, 0).unwrap(), 3000);
}
