use std::{
    fs::{write, File},
    io::ErrorKind,
    net::TcpListener,
    path::Path,
};

use aya::{
    programs::{lsm_cgroup::LsmCgroup, Lsm},
    util::KernelVersion,
    Btf, Ebpf,
};
use tempfile::TempPath;

#[test]
#[ignore = "LSM programs need a special kernel config, which is not supported by GitHub runners[waiting on PR: 1063]."]
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

    let temp_cgroup = TempPath::from_path(Path::new("/sys/fs/cgroup/lsm_cgroup_test"));
    let temp_proc = temp_cgroup.join("cgroup.procs");

    prog.attach(File::open(temp_cgroup).unwrap()).unwrap();

    let pid = std::process::id();
    write(temp_proc, format!("{}\n", pid)).expect("could not write into procs file");

    assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Err(e) => assert_eq!(
        e.kind(), ErrorKind::PermissionDenied));
}

#[test]
#[ignore = "LSM programs need a special kernel config, which is not supported by GitHub runners[waiting on PR: 1063]."]
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
