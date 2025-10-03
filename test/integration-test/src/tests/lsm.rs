use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    programs::{Lsm, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
};

macro_rules! expect_permission_denied {
    ($result:expr) => {
        let result = $result;
        if !std::fs::read_to_string("/sys/kernel/security/lsm").unwrap().contains("bpf") {
            assert_matches!(result, Ok(_));
        } else {
            assert_matches!(result, Err(e) => assert_eq!(
                e.kind(), std::io::ErrorKind::PermissionDenied)
            );
        }
    };
}

#[test]
fn lsm() {
    let btf = Btf::from_sys_fs().unwrap();

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog = bpf.program_mut("test_lsm").unwrap();
    let prog: &mut Lsm = prog.try_into().unwrap();
    prog.load("socket_bind", &btf).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    let link_id = {
        let result = prog.attach();
        if !is_program_supported(ProgramType::Lsm).unwrap() {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            eprintln!("skipping test - LSM programs not supported");
            return;
        }
        result.unwrap()
    };

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    prog.detach(link_id).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));
}
