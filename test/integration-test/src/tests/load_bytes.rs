use aya::{
    Ebpf,
    programs::{ProgramType, SocketFilter},
    sys::is_program_supported,
};

#[test_log::test]
fn test_load_bytes() {
    // Ensure SocketFilter programs are supported on this kernel before running the test.
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    // Load the eBPF program from in-memory bytes and prepare the SocketFilter program.
    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut SocketFilter = bpf
        .program_mut("fix_test_load_bytes")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
}
