use aya::{
    Ebpf,
    programs::{ProgramType, SocketFilter},
    sys::is_program_supported,
};

#[test_log::test]
fn test_load_bytes() {
    // This ProgramType and these two MapTypes are needed because the MAP_TEST sample program uses all three.
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    // Load the eBPF program to create the file descriptor associated with the BAR map. This is
    // required to read and write to the map which we test below.
    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut SocketFilter = bpf
        .program_mut("fix_test_load_bytes")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
}
