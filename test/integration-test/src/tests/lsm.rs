use assert_matches::assert_matches;
use aya::{
    Ebpf,
    programs::{Lsm, LsmAttachType, LsmCgroup, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
    test_helpers::Cgroup,
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
    let Some(btf) = super::kernel_btf() else {
        return;
    };

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog = bpf.program_mut("test_lsm").unwrap();
    let prog: &mut Lsm = prog.try_into().unwrap();
    prog.load("socket_bind", &btf).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    let mac_attach_supported = is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap();
    let link_id = match prog.attach() {
        Ok(link_id) => {
            assert!(mac_attach_supported);
            link_id
        }
        Err(error) => {
            assert!(
                !mac_attach_supported,
                "unexpected LSM attach error: {error}"
            );
            assert_matches!(error, ProgramError::SyscallError(SyscallError { call, io_error }) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            return;
        }
    };

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    prog.detach(link_id).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));
}

#[test]
fn lsm_cgroup() {
    let Some(btf) = super::kernel_btf() else {
        return;
    };
    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog = bpf.program_mut("test_lsm_cgroup").unwrap();
    let prog: &mut LsmCgroup = prog.try_into().unwrap();
    let cgroup_lsm_supported =
        is_program_supported(ProgramType::Lsm(LsmAttachType::Cgroup)).unwrap();
    match prog.load("socket_bind", &btf) {
        Ok(()) => assert!(cgroup_lsm_supported),
        Err(err) => match err {
            ProgramError::LoadError {
                io_error,
                verifier_log,
            } => {
                assert!(!cgroup_lsm_supported, "{verifier_log}");
                assert_eq!(
                    io_error.raw_os_error(),
                    Some(libc::EINVAL),
                    "{verifier_log}"
                );
                assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
                return;
            }
            err => panic!("unexpected error loading LSM cgroup program: {err}"),
        },
    }

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    let pid = std::process::id();
    let root = Cgroup::root().unwrap();
    let cgroup = root.create_child("aya-test-lsm-cgroup").unwrap();

    let mac_attach_supported = is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap();
    let link_id = match prog.attach(cgroup.fd().unwrap()) {
        Ok(link_id) => link_id,
        Err(error) => {
            assert!(
                !mac_attach_supported,
                "unexpected LSM cgroup attach error: {error}"
            );
            assert_matches!(error, ProgramError::SyscallError(SyscallError { call, io_error }) => {
                assert_eq!(call, "bpf_link_create");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            return;
        }
    };

    let cgroup = cgroup.into_cgroup();

    cgroup.write_pid(pid).unwrap();

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    root.write_pid(pid).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    cgroup.write_pid(pid).unwrap();

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    prog.detach(link_id).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));
}
