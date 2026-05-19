use aya::{
    Ebpf,
    maps::{Array, ArrayOfMaps, HashOfMaps, MapData},
    programs::{UProbe, uprobe::UProbeScope},
};
use integration_common::btf_map_of_maps::INNER_MAX_ENTRIES;
use test_case::test_case;

#[derive(Clone, Copy, Debug)]
enum MapKind {
    Array,
    Hash,
}

impl MapKind {
    fn insert_inner(self, ebpf: &mut Ebpf, key: u32, inner: &Array<MapData, u32>) {
        match self {
            Self::Array => {
                let mut outer: ArrayOfMaps<&mut MapData, Array<MapData, u32>> =
                    ebpf.map_mut("ARRAY_OF_MAPS").unwrap().try_into().unwrap();
                outer.set(key, inner, 0).unwrap();
            }
            Self::Hash => {
                let mut outer: HashOfMaps<&mut MapData, u32, Array<MapData, u32>> =
                    ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
                outer.insert(key, inner, 0).unwrap();
            }
        }
    }

    fn trigger_basic(self) {
        match self {
            Self::Array => trigger_btf_array_of_maps(),
            Self::Hash => trigger_btf_hash_of_maps(),
        }
    }

    fn trigger_get_value(self) {
        match self {
            Self::Array => trigger_btf_array_of_maps_get_value(),
            Self::Hash => trigger_btf_hash_of_maps_get_value(),
        }
    }
}

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
    prog.attach(
        format!("trigger_{name}").as_str(),
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();
}

/// Reads `RESULTS[index]` and asserts `value` and `ran == 1`.
fn assert_result(ebpf: &Ebpf, index: u32, expected_value: u32) {
    let results: Array<&MapData, integration_common::btf_map_of_maps::TestResult> =
        ebpf.map("RESULTS").unwrap().try_into().unwrap();
    let result = results.get(&index, 0).unwrap();
    assert_eq!(result.value, expected_value);
    assert_eq!(result.ran, 1);
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

#[test_log::test(test_case(MapKind::Array, "btf_array_of_maps", 0, 42 ; "array_of_maps"))]
#[test_case(MapKind::Hash, "btf_hash_of_maps", 1, 55 ; "hash_of_maps")]
fn btf_map_of_maps(kind: MapKind, name: &str, result_index: u32, expected: u32) {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner: Array<MapData, u32> = Array::create(INNER_MAX_ENTRIES, 0).unwrap();
    inner.set(0, expected, 0).unwrap();

    kind.insert_inner(&mut ebpf, 0, &inner);

    load_and_attach(&mut ebpf, name);
    kind.trigger_basic();
    assert_result(&ebpf, result_index, expected);
}

#[test_log::test(test_case(MapKind::Array, "btf_array_of_maps_get_value", 2, 77, 99 ; "array_of_maps"))]
#[test_case(MapKind::Hash, "btf_hash_of_maps_get_value", 3, 55, 88 ; "hash_of_maps")]
fn btf_map_of_maps_get_value(
    kind: MapKind,
    name: &str,
    result_index: u32,
    expected_get: u32,
    expected_mut_write: u32,
) {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner_1: Array<MapData, u32> = Array::create(INNER_MAX_ENTRIES, 0).unwrap();
    inner_1.set(0, expected_get, 0).unwrap();

    let mut inner_2: Array<MapData, u32> = Array::create(INNER_MAX_ENTRIES, 0).unwrap();
    inner_2.set(0, 0u32, 0).unwrap();

    kind.insert_inner(&mut ebpf, 0, &inner_1);
    kind.insert_inner(&mut ebpf, 1, &inner_2);

    load_and_attach(&mut ebpf, name);
    kind.trigger_get_value();

    assert_result(&ebpf, result_index, expected_get);
    assert_eq!(inner_2.get(&0, 0).unwrap(), expected_mut_write);
}

/// Inserting an inner map into a `HashOfMaps` does not consume the userspace handle:
/// the original `Array` remains readable and writable after the insert.
#[test_log::test]
fn btf_hash_of_maps_dynamic() {
    let mut ebpf = Ebpf::load(crate::BTF_MAP_OF_MAPS).unwrap();

    let mut inner_1: Array<MapData, u32> = Array::create(INNER_MAX_ENTRIES, 0).unwrap();
    let mut inner_2: Array<MapData, u32> = Array::create(INNER_MAX_ENTRIES, 0).unwrap();

    inner_1.set(0, 1000u32, 0).unwrap();
    inner_2.set(0, 2000u32, 0).unwrap();

    {
        let mut outer: HashOfMaps<&mut MapData, u32, Array<MapData, u32>> =
            ebpf.map_mut("HASH_OF_MAPS").unwrap().try_into().unwrap();
        outer.insert(10u32, &inner_1, 0).unwrap();
        outer.insert(11u32, &inner_2, 0).unwrap();
    }

    assert_eq!(inner_1.get(&0, 0).unwrap(), 1000);
    assert_eq!(inner_2.get(&0, 0).unwrap(), 2000);

    inner_1.set(1, 3000u32, 0).unwrap();
    assert_eq!(inner_1.get(&1, 0).unwrap(), 3000);
}
