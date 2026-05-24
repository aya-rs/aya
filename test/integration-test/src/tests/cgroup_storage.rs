#![expect(
    deprecated,
    reason = "exercising the deprecated cgroup storage map types"
)]

use std::{
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::unix::fs::MetadataExt as _,
    process,
};

use aya::{
    EbpfLoader,
    maps::{CgroupStorage, CgroupStorageKey, MapType, PerCpuCgroupStorage},
    programs::{CgroupAttachMode, CgroupSockAddr},
    sys::is_map_supported,
    util::KernelVersion,
};
use aya_obj::generated::bpf_attach_type::BPF_CGROUP_INET4_CONNECT;
use rstest::rstest;

use crate::utils::{Cgroup, NetNsGuard, is_cgroup2};

#[rstest]
#[case::legacy("STORAGE_LEGACY", "PERCPU_LEGACY", "connect4_legacy")]
#[case::btf("STORAGE", "PERCPU", "connect4_btf")]
#[test_attr(test_log::test)]
fn cgroup_storage(#[case] storage_map: &str, #[case] percpu_map: &str, #[case] prog: &str) {
    if !is_map_supported(MapType::CgroupStorage).unwrap()
        || !is_map_supported(MapType::PerCpuCgroupStorage).unwrap()
    {
        eprintln!("skipping test - cgroup storage maps not supported");
        return;
    }

    if !is_cgroup2() {
        eprintln!("skipping test - /sys/fs/cgroup is not cgroup2");
        return;
    }

    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(4, 20, 0) {
        eprintln!(
            "skipping test - per-cpu cgroup storage added in 4.20, kernel is {kernel_version:?}"
        );
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::CGROUP_STORAGE)
        .expect("load cgroup_storage program");

    let _netns = NetNsGuard::new();
    let root = Cgroup::root();
    let cgroup = root.create_child(prog);
    let cgroup_inode_id = cgroup.fd().metadata().expect("cgroup metadata").ino();

    {
        let program: &mut CgroupSockAddr = bpf
            .program_mut(prog)
            .unwrap_or_else(|| panic!("missing program {prog}"))
            .try_into()
            .unwrap_or_else(|err| panic!("program {prog} is not a cgroup_sock_addr: {err}"));
        program
            .load()
            .unwrap_or_else(|err| panic!("load {prog}: {err}"));
        program
            .attach(cgroup.fd(), CgroupAttachMode::Single)
            .unwrap_or_else(|err| panic!("attach {prog}: {err}"));
    }

    let cgroup = cgroup.into_cgroup();
    cgroup.write_pid(process::id());

    // A single connect over loopback fires the connect4 program exactly once.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    TcpStream::connect(addr).unwrap();

    let key = CgroupStorageKey::new(cgroup_inode_id, BPF_CGROUP_INET4_CONNECT as u32);

    let storage = CgroupStorage::<_, u64>::try_from(bpf.map(storage_map).unwrap()).unwrap();
    assert_eq!(storage.get(key, 0).unwrap(), 1);

    let percpu = PerCpuCgroupStorage::<_, u64>::try_from(bpf.map(percpu_map).unwrap()).unwrap();
    let percpu = percpu.get(key, 0).unwrap();
    assert_eq!(percpu.iter().sum::<u64>(), 1);
}
