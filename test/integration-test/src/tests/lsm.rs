use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    programs::{Lsm, LsmAttachType, LsmCgroup, ProgramError, ProgramType, links::FdLink},
    sys::{SyscallError, is_program_supported},
    test_helpers::Cgroup,
    util::KernelVersion,
};
use rstest::rstest;

use super::assert_link_program;

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
    let root = Cgroup::root().unwrap();
    let cgroup = root.create_child("aya-test-lsm-cgroup").unwrap();

    let link_id = {
        let result = prog.attach(cgroup.fd().unwrap());

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

    cgroup.write_pid(pid).unwrap();

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    root.write_pid(pid).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    cgroup.write_pid(pid).unwrap();

    expect_permission_denied!(std::net::TcpListener::bind("127.0.0.1:0"));

    prog.detach(link_id).unwrap();

    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));
}

#[rstest]
#[case::detach(false)]
#[case::drop(true)]
#[test_attr(test_log::test)]
fn adopt_link_lsm_cgroup(#[case] drop_program: bool) {
    if !is_program_supported(ProgramType::Lsm(LsmAttachType::Cgroup)).unwrap() {
        eprintln!("skipping test - LSM cgroup programs not supported");
        return;
    }
    if cfg!(target_arch = "aarch64")
        && KernelVersion::current().unwrap() < KernelVersion::new(6, 4, 0)
    {
        eprintln!("skipping test - LSM cgroup programs not supported at attach");
        return;
    }
    if !std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .contains("bpf")
    {
        eprintln!("skipping test - BPF LSM hooks are not enabled");
        return;
    }

    let root = Cgroup::root().unwrap();
    let cgroup = root
        .create_child(&format!("aya-adopt-lsm-{drop_program}"))
        .unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let mut old_bpf = Ebpf::load(crate::TEST).unwrap();
    let old: &mut LsmCgroup = old_bpf
        .program_mut("test_lsm_cgroup")
        .unwrap()
        .try_into()
        .unwrap();
    old.load("socket_bind", &btf).unwrap();
    let id = old.attach(cgroup.fd().unwrap()).unwrap();
    let link: FdLink = old.take_link(id).unwrap().into();
    let old_info = link.info().unwrap();

    // Enter the attached cgroup so a denied bind proves the old program is active.
    let cgroup = cgroup.into_cgroup();
    cgroup.write_pid(std::process::id()).unwrap();
    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Err(err) => {
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    });

    let mut new_bpf = Ebpf::load(crate::TEST).unwrap();
    let new: &mut LsmCgroup = new_bpf
        .program_mut("allow_bind")
        .unwrap()
        .try_into()
        .unwrap();
    new.load("socket_bind", &btf).unwrap();
    let new_program_id = new_bpf.program("allow_bind").unwrap().info().unwrap().id();
    assert_ne!(old_info.program_id(), new_program_id);
    let new: &mut LsmCgroup = new_bpf
        .program_mut("allow_bind")
        .unwrap()
        .try_into()
        .unwrap();
    // Adoption must switch the existing link to allow_bind and keep it active
    // after the old owner is dropped.
    let id = new.adopt_link(link.into()).unwrap();
    drop(old_bpf);
    assert_link_program(old_info.id(), Some(new_program_id));
    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));

    // Both cleanup paths must remove the link and leave binding allowed.
    if drop_program {
        drop(new_bpf);
    } else {
        new.detach(id).unwrap();
    }
    assert_link_program(old_info.id(), None);
    assert_matches!(std::net::TcpListener::bind("127.0.0.1:0"), Ok(_));
}
