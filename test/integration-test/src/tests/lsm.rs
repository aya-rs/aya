use std::{io::ErrorKind, net::TcpListener};

use aya::{
    Btf, Ebpf,
    programs::{Lsm, lsm_cgroup::LsmCgroup},
    sys::is_program_supported,
};

use crate::utils::Cgroup;

fn is_lsm_bpf_enabled() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .contains("bpf")
}

#[test]
fn lsm_cgroup() {
    if !(is_program_supported(aya::programs::ProgramType::Lsm).unwrap() && is_lsm_bpf_enabled()) {
        eprintln!("LSM programs are not supported");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut LsmCgroup = bpf
        .program_mut("test_lsmcgroup")
        .unwrap()
        .try_into()
        .unwrap();
    let btf = Btf::from_sys_fs().expect("could not get btf from sys");
    prog.load("socket_bind", &btf).unwrap();

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(_));

    let root = Cgroup::root();
    let cgroup = root.create_child("aya-test-lsm-cgroup");
    let fd = cgroup.fd();

    let link_id = prog.attach(&fd).unwrap();
    let _guard = scopeguard::guard((), |()| {
        prog.detach(link_id).unwrap();
    });

    let pid = std::process::id();

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(_));

    cgroup.into_cgroup().write_pid(pid);

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Err(e) => assert_eq!(
        e.kind(), ErrorKind::PermissionDenied));

    root.write_pid(pid);

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(_));
}

#[test]
fn lsm() {
    if !(is_program_supported(aya::programs::ProgramType::Lsm).unwrap() && is_lsm_bpf_enabled()) {
        eprintln!("LSM programs are not supported");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut Lsm = bpf.program_mut("test_lsm").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().expect("could not get btf from sys");
    prog.load("socket_bind", &btf).unwrap();

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(_));

    prog.attach().unwrap();

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Err(e) => assert_eq!(
        e.kind(), ErrorKind::PermissionDenied)
    );
}
