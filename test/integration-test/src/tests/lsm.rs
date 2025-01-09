use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Write as _},
    net::TcpListener,
    path::Path,
};

use aya::{
    Btf, Ebpf,
    programs::{Lsm, lsm_cgroup::LsmCgroup},
    util::KernelVersion,
};

#[test]
//#[ignore = "LSM programs need a special kernel config, which is not supported by GitHub runners[waiting on PR: 1063]."]
fn lsm_cgroup() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 0, 0) {
        eprintln!("skipping lsm_cgroup test on kernel {kernel_version:?}");
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

    let cgroup_dir = Path::new("/sys/fs/cgroup/lsm_cgroup_test");
    std::fs::create_dir_all(cgroup_dir).expect("could not create cgroup dir");

    let proc_path = cgroup_dir.join("cgroup.procs");

    let link_id = prog.attach(File::open(cgroup_dir).unwrap()).unwrap();
    let _guard = scopeguard::guard((), |()| {
        prog.detach(link_id).unwrap();
    });

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(_));

    let pid = std::process::id();
    let mut procfs = OpenOptions::new().append(true).open(proc_path).unwrap();
    write!(procfs, "{}", pid).expect("could not write into procs file");

    let _guard = scopeguard::guard((), |()| {
        let mut file = OpenOptions::new()
            .append(true)
            .open("/sys/fs/cgroup/cgroup.procs")
            .unwrap();
        write!(file, "{}", pid).expect("could not write into procs file");
        std::fs::remove_dir(cgroup_dir).unwrap();
    });

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Err(e) => assert_eq!(
        e.kind(), ErrorKind::PermissionDenied));
}

#[test]
//#[ignore = "LSM programs need a special kernel config, which is not supported by GitHub runners[waiting on PR: 1063]."]
fn lsm() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 7, 0) {
        eprintln!("skipping lsm test on kernel {kernel_version:?}");
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
