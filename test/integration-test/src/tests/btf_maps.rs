//! BTF map loading with Aya and libbpf.

use aya::{Ebpf, maps::Array, programs::UProbe};

#[test_log::test]
fn aya_can_load_multidimensional_array() {
    let mut ebpf = Ebpf::load(crate::BTF_MAPS_PLAIN).unwrap();
    let program: &mut UProbe = ebpf
        .program_mut("btf_maps_plain")
        .unwrap()
        .try_into()
        .unwrap();
    // The program reads the last element, beyond the size of a single row.
    program.load().unwrap();

    let mut array =
        Array::<_, [[u32; 3]; 2]>::try_from(ebpf.take_map("BTF_ARRAY").unwrap()).unwrap();
    let value = [[1, 2, 3], [4, 5, 6]];
    array.set(0, &value, 0).unwrap();
    assert_eq!(array.get(&0, 0).unwrap(), value);
}

/// Test that libbpf can open and load a Rust eBPF program with `btf_maps`.
///
/// This verifies that our BTF map definitions produce metadata that libbpf
/// can parse and load.
#[test_log::test]
fn libbpf_can_load_btf_maps() {
    // Use libbpf-rs to open the object file.
    let obj = libbpf_rs::ObjectBuilder::default()
        .open_memory(crate::BTF_MAPS_PLAIN)
        .expect("libbpf failed to open Rust eBPF object with btf_maps");

    // Verify libbpf can see the BTF_ARRAY map.

    // Materialize the maps because `OpenMap::name` returns the wrong lifetime.
    let map_names: Vec<_> = obj.maps().map(|map| map.name()).collect();
    if !map_names.iter().any(|name| *name == "BTF_ARRAY") {
        let display_map_names = map_names.join(std::ffi::OsStr::new(", "));
        panic!(
            "libbpf should find the BTF_ARRAY map defined with btf_map macro, found: {}",
            display_map_names.display()
        );
    }
}
