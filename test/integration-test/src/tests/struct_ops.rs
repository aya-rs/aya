use aya::{Btf, Ebpf, programs::StructOps};

/// Test that struct_ops programs are parsed correctly from the ELF.
///
/// Verifies:
/// - Multiple struct_ops programs can exist in one object
/// - Programs are accessed by their Rust function name (not the section suffix)
/// - Programs can be retrieved by name
#[test_log::test]
fn struct_ops_parse_multiple_programs() {
    let ebpf = Ebpf::load(crate::STRUCT_OPS_TEST).unwrap();

    // Test that all three struct_ops programs are found
    // Note: Programs are accessed by their Rust function names
    let programs: Vec<_> = ebpf.programs().map(|(name, _)| name).collect();

    assert!(
        programs.contains(&"struct_ops_test_callback"),
        "missing struct_ops_test_callback, found: {programs:?}"
    );
    // The renamed callback uses the function name, not the section suffix
    assert!(
        programs.contains(&"struct_ops_second_callback"),
        "missing struct_ops_second_callback, found: {programs:?}"
    );
    assert!(
        programs.contains(&"struct_ops_sleepable_callback"),
        "missing struct_ops_sleepable_callback, found: {programs:?}"
    );
}

/// Test that struct_ops programs have the correct program type.
#[test_log::test]
fn struct_ops_program_type() {
    let ebpf = Ebpf::load(crate::STRUCT_OPS_TEST).unwrap();

    // Programs are accessed by their Rust function names
    for name in [
        "struct_ops_test_callback",
        "struct_ops_second_callback",
        "struct_ops_sleepable_callback",
    ] {
        let prog = ebpf.program(name).expect(&format!("program {name} not found"));

        assert!(
            matches!(prog.prog_type(), aya::programs::ProgramType::StructOps),
            "expected StructOps program type for {name}"
        );
    }
}

/// Test that struct_ops programs can be converted to the StructOps type.
#[test_log::test]
fn struct_ops_type_conversion() {
    let mut ebpf = Ebpf::load(crate::STRUCT_OPS_TEST).unwrap();

    // Each program should be convertible to StructOps
    let prog: &mut StructOps = ebpf
        .program_mut("struct_ops_test_callback")
        .expect("program not found")
        .try_into()
        .expect("failed to convert to StructOps");

    // Verify the member name matches the section name
    assert_eq!(
        prog.member_name(),
        "struct_ops_test_callback",
        "member_name should match the program's section suffix"
    );
}

/// Test that the member_name reflects the struct_ops section suffix.
///
/// When using `#[struct_ops(name = "another_callback")]`, the program is
/// accessed by its Rust function name, but member_name() returns the
/// section suffix (the name attribute value).
#[test_log::test]
fn struct_ops_renamed_member_name() {
    let mut ebpf = Ebpf::load(crate::STRUCT_OPS_TEST).unwrap();

    // Access the program by its Rust function name
    let prog: &mut StructOps = ebpf
        .program_mut("struct_ops_second_callback")
        .expect("program not found")
        .try_into()
        .expect("failed to convert to StructOps");

    // The member_name should be "another_callback" (from the name attribute),
    // which is the struct_ops callback name used for BTF lookups
    assert_eq!(
        prog.member_name(),
        "another_callback",
        "member_name should match the section suffix (name attribute), not the function name"
    );
}

/// Test that kernel BTF is available and contains common struct_ops types.
///
/// This test verifies that the BTF infrastructure works, which is required
/// for struct_ops loading. It checks for well-known struct_ops types that
/// should be present in modern kernels.
#[test_log::test]
fn struct_ops_btf_availability() {
    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(e) => {
            eprintln!("skipping test - kernel BTF not available: {e}");
            return;
        }
    };

    // tcp_congestion_ops has been available since kernel 5.6
    // This is a basic sanity check that BTF type lookup works
    let result = btf.id_by_type_name_kind("tcp_congestion_ops", aya_obj::btf::BtfKind::Struct);

    match result {
        Ok(type_id) => {
            assert!(type_id > 0, "tcp_congestion_ops should have a valid type ID");
        }
        Err(e) => {
            // This is not necessarily an error - older kernels may not have it
            eprintln!("tcp_congestion_ops not found in BTF (may be expected on older kernels): {e}");
        }
    }
}

/// Test that struct member lookup works in BTF.
///
/// This is important for struct_ops because we need to resolve member
/// names to indices when loading programs.
#[test_log::test]
fn struct_ops_btf_member_lookup() {
    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(e) => {
            eprintln!("skipping test - kernel BTF not available: {e}");
            return;
        }
    };

    // Look up tcp_congestion_ops struct
    let struct_id = match btf.id_by_type_name_kind("tcp_congestion_ops", aya_obj::btf::BtfKind::Struct) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("skipping test - tcp_congestion_ops not in BTF: {e}");
            return;
        }
    };

    // tcp_congestion_ops should have a "name" member (char[16] for the algorithm name)
    let name_idx = btf.struct_member_index(struct_id, "name");
    assert!(
        name_idx.is_ok(),
        "tcp_congestion_ops should have a 'name' member: {:?}",
        name_idx.err()
    );

    // It should also have "ssthresh" which is a required callback
    let ssthresh_idx = btf.struct_member_index(struct_id, "ssthresh");
    assert!(
        ssthresh_idx.is_ok(),
        "tcp_congestion_ops should have a 'ssthresh' member: {:?}",
        ssthresh_idx.err()
    );

    // Member indices should be different
    assert_ne!(
        name_idx.unwrap(),
        ssthresh_idx.unwrap(),
        "different members should have different indices"
    );
}

/// Test error handling for non-existent struct_ops type.
#[test_log::test]
fn struct_ops_btf_unknown_type() {
    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(e) => {
            eprintln!("skipping test - kernel BTF not available: {e}");
            return;
        }
    };

    // Looking up a non-existent type should fail
    let result = btf.id_by_type_name_kind(
        "definitely_not_a_real_struct_ops_type_12345",
        aya_obj::btf::BtfKind::Struct,
    );

    assert!(
        result.is_err(),
        "looking up non-existent type should fail"
    );
}
