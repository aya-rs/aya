//! Test that BTF maps can be loaded.
//!
//! This test loads a C BPF program that uses BTF map definitions.
//! If this works, it proves the BTF structure is valid for libbpf.
//! Our Rust btf_maps should produce equivalent BTF structures.

use aya::Ebpf;

#[test_log::test]
fn load_btf_maps_c_program() {
    // Load the C BPF program with BTF maps
    let ebpf = Ebpf::load(crate::BTF_MAPS).expect("failed to load BTF_MAPS");

    // Verify the maps exist
    assert!(ebpf.map("btf_array").is_some(), "btf_array map not found");
    assert!(
        ebpf.map("btf_ringbuf").is_some(),
        "btf_ringbuf map not found"
    );
}
