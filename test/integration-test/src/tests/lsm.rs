use std::{fs::File, io::{ErrorKind, Write}, path::Path};
use aya::{programs::Lsm, util::KernelVersion, Btf, Ebpf};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use nix::{
    sys::wait::waitpid,
    unistd::{fork, getpid, ForkResult},
};

#[test]
fn lsm_cgroup() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 0, 0) {
        eprintln!("skipping lsm_cgroup test on kernel {kernel_version:?}");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut Lsm = bpf.program_mut("test_lsmcgroup").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().expect("could not get btf from sys");
    if let Err(err) = prog.load("socket_bind", &btf) {
        panic!("{err}");
    }

    let cgroup_path = Path::new(".").join("/sys/fs/cgroup/").join("lsm_cgroup_test");

    let _ = std::fs::create_dir_all( cgroup_path.clone()).expect("could not create the cgroup dir");

    let p = prog.attach(
        Some(File::open(cgroup_path.clone()).unwrap()),
    )
    .unwrap();

    unsafe {
        match fork().expect("Failed to fork process") {
            ForkResult::Parent { child } => {
                waitpid(Some(child), None).unwrap();

                let pid = getpid();

                let mut f = File::create(cgroup_path.join("cgroup.procs")).expect("could not open cgroup procs");
                f.write_fmt(format_args!("{}",pid.as_raw() as u64)).expect("could not write into procs file");
                
                assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Err(e) => assert_eq!(
                    e.kind(), ErrorKind::PermissionDenied)
                );
            }
            ForkResult::Child => {
                assert_matches::assert_matches!(TcpListener::bind("127.0.0.1:12345"), Ok(listener) => assert_eq!(
                    listener.local_addr().unwrap(), SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 12345)))
                );
            }
        }
    }
}
