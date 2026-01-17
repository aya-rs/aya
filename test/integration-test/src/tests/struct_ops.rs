use aya::{Ebpf, programs::StructOps};

/// Test that struct_ops section parsing works correctly.
///
/// This test verifies that:
/// 1. The struct_ops section is recognized and parsed
/// 2. The program can be retrieved as a StructOps type
///
/// Note: Actually loading and attaching struct_ops programs requires
/// additional kernel support and a properly defined struct_ops map,
/// which is more complex to test.
#[test_log::test]
fn struct_ops_parse() {
    let mut ebpf = Ebpf::load(crate::STRUCT_OPS_TEST).unwrap();

    // Verify we can get the program as a StructOps type
    let prog: &mut StructOps = ebpf
        .program_mut("struct_ops_test_callback")
        .expect("program not found")
        .try_into()
        .expect("wrong program type");

    // The program should exist but we can't easily load it without
    // a proper struct_ops map definition.
    // This test at least verifies the parsing works.
    let _ = prog;
}

/// Test that struct_ops program info is correct.
#[test_log::test]
fn struct_ops_program_type() {
    let ebpf = Ebpf::load(crate::STRUCT_OPS_TEST).unwrap();

    let prog = ebpf
        .program("struct_ops_test_callback")
        .expect("program not found");

    // Verify the program type is StructOps
    assert!(
        matches!(prog.prog_type(), aya::programs::ProgramType::StructOps),
        "expected StructOps program type"
    );
}
