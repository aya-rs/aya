//! BTF map loading with Aya and parsing with libbpf.

use std::ffi::OsStr;

use aya::{EbpfLoader, maps::Array, programs::UProbe};
use integration_common::btf_maps::ArrayValue;

#[test_log::test]
fn aya_can_load_multidimensional_array() {
    let directory = tempfile::Builder::new()
        .prefix("btf-map-pin-")
        .tempdir_in("/sys/fs/bpf")
        .unwrap();
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(directory.path())
        .load(crate::BTF_MAPS_PLAIN)
        .unwrap();
    for name in ["BTF_ARRAY", "BTF_OUTER"] {
        assert!(directory.path().join(name).exists());
    }
    let program: &mut UProbe = ebpf
        .program_mut("btf_maps_plain")
        .unwrap()
        .try_into()
        .unwrap();
    // The program reads the last element, beyond the size of a single row.
    program.load().unwrap();

    let mut array = Array::<_, ArrayValue>::try_from(ebpf.take_map("BTF_ARRAY").unwrap()).unwrap();
    let value = [[1, 2, 3], [4, 5, 6]];
    array.set(0, &value, 0).unwrap();
    assert_eq!(array.get(&0, 0).unwrap(), value);
}

#[test_log::test]
fn libbpf_can_open_btf_maps() {
    let obj = libbpf_rs::ObjectBuilder::default()
        .open_memory(crate::BTF_MAPS_PLAIN)
        .expect("libbpf failed to open Rust eBPF object with btf_maps");

    let mut maps: Vec<_> = obj
        .maps()
        .map(|map| (map.name(), map.value_size()))
        .collect();
    maps.sort_unstable();
    assert_eq!(
        maps,
        [
            ("BTF_ARRAY", size_of::<ArrayValue>()),
            ("BTF_OUTER", size_of::<u32>()),
            ("BTF_RING_BUF", size_of::<u32>()),
        ]
        .map(|(name, value_size)| (OsStr::new(name), value_size as u32))
    );
}
