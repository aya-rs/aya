//! Test that libbpf can load BTF maps from Rust eBPF programs.
//!
//! This test verifies that the BTF metadata produced by aya-ebpf's btf_maps
//! is compatible with libbpf's loader.

/// Test that libbpf can open and load a Rust eBPF program with btf_maps.
///
/// This verifies that our BTF map definitions produce metadata that libbpf
/// can parse and load.
#[test_log::test]
fn libbpf_can_load_btf_maps() {
    // Use libbpf-rs to open the object file
    let obj = libbpf_rs::ObjectBuilder::default()
        .open_memory(crate::BTF_MAPS_PLAIN)
        .expect("libbpf failed to open Rust eBPF object with btf_maps");

    // Verify libbpf can see the BTF_ARRAY map
    assert!(
        obj.maps().any(|m| m.name() == "BTF_ARRAY"),
        "libbpf should find the BTF_ARRAY map defined with btf_map macro"
    );
}
