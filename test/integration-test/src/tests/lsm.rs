use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    programs::{Lsm, LsmAttachType, LsmCgroup, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
    util::KernelVersion,
};

use crate::utils::Cgroup;

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
        if !is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap() {
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

#[test]
fn lsm_cgroup() {
    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog = bpf.program_mut("test_lsm_cgroup").unwrap();
    let prog: &mut LsmCgroup = prog.try_into().unwrap();
    let btf = Btf::from_sys_fs().expect("could not get btf from sys");
    match prog.load("socket_bind", &btf) {
        Ok(()) => {}
        Err(err) => match err {
            ProgramError::LoadError { io_error, .. }
                if !is_program_supported(ProgramType::Lsm(LsmAttachType::Cgroup)).unwrap() =>
            {
                assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                eprintln!("skipping test - LSM cgroup programs not supported at load");
                return;
            }
            err => panic!("unexpected error loading LSM cgroup program: {err}"),
        },
    }

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    let pid = std::process::id();
    let root = Cgroup::root();
    let cgroup = root.create_child("aya-test-lsm-cgroup");

    let link_id = {
        let result = prog.attach(cgroup.fd());

        // See https://www.exein.io/blog/exploring-bpf-lsm-support-on-aarch64-with-ftrace.
        if cfg!(target_arch = "aarch64")
            && KernelVersion::current().unwrap() < KernelVersion::new(6, 4, 0)
        {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_link_create");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            eprintln!("skipping test - LSM cgroup programs not supported at attach");
            return;
        }
        result.unwrap()
    };

    let cgroup = cgroup.into_cgroup();

    cgroup.write_pid(pid);

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    root.write_pid(pid);

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    cgroup.write_pid(pid);

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    prog.detach(link_id).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));
}
