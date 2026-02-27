use aya::{
    Ebpf,
    programs::{ProgramType, SocketFilter},
    sys::is_program_supported,
};

// Load the eBPF socket filter program from the embedded bytes and ensure it loads
// successfully (i.e., passes verification) using Ebpf::load and prog.load().
#[test_log::test]
fn test_load_bytes() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut SocketFilter = bpf
        .program_mut("fix_test_load_bytes")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    // should pass verification
}
