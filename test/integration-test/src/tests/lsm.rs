use std::{
    fs::File,
    io::{ErrorKind, Write},
    net::TcpListener,
    path::Path,
};

use aya::{
    programs::{lsm_cgroup::LsmCgroup, Lsm},
    util::KernelVersion,
    Btf, Ebpf,
};
use nix::{
    sys::wait::waitpid,
    unistd::{fork, getpid, ForkResult},
};

#[test]//#[ignore = "Lsm program type requires a special kernel config to be enabled and github runners dont allow us to configure kernel parameters for linux vms[waiting on this pr: 1063]"]
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

    let cgroup_path = Path::new("/sys/fs/cgroup/lsm_cgroup_test");

    prog.attach(File::open(cgroup_path).unwrap()).unwrap();

    match unsafe { fork().expect("Failed to fork process") } {
        ForkResult::Parent { child } => {
            waitpid(Some(child), None).unwrap();
            let pid = getpid();
            let mut f = File::create(cgroup_path.join("cgroup.procs"))
                .expect("could not open cgroup procs");
            write!(&mut f, "{pid}")
                .expect("could not write into procs file");

            assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Err(e) => assert_eq!(
                e.kind(), ErrorKind::PermissionDenied)
            );
        }
        ForkResult::Child => {
            assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(_));
        }
    }
}

#[test]//#[ignore = "Lsm program type requires a special kernel config to be enabled and github runners dont allow us to configure kernel parameters for linux vms[waiting on this pr: 1063]"]
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
