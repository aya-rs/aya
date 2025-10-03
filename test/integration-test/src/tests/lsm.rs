use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    programs::{Lsm, ProgramError, ProgramType},
    sys::SyscallError,
    sys::is_program_supported,
};

#[test]
fn lsm() {
    let btf = Btf::from_sys_fs().unwrap();

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog = bpf.program_mut("test_file_open").unwrap();
    let prog: &mut Lsm = prog.try_into().unwrap();
    prog.load("file_open", &btf).unwrap();

    assert_matches!(std::fs::File::open("/proc/self/exe"), Ok(_));

    let link_id = {
        let result = prog.attach();
        if !is_program_supported(ProgramType::Lsm).unwrap() {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            eprintln!("skipping test - lsm program not supported");
            return;
        }
        result.unwrap()
    };

    assert_matches!(std::fs::File::open("/proc/self/exe"), Err(e) => assert_eq!(
        e.kind(), std::io::ErrorKind::PermissionDenied)
    );

    prog.detach(link_id).unwrap();

    assert_matches!(std::fs::File::open("/proc/self/exe"), Ok(_));
}
