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
    test_helpers::{Cgroup, NetNsGuard},
};
use aya_obj::generated::bpf_attach_type::BPF_CGROUP_INET4_CONNECT;
use rstest::rstest;

#[rstest]
#[case::legacy("STORAGE_LEGACY", "PERCPU_LEGACY", "connect4_legacy")]
#[case::btf("STORAGE", "PERCPU", "connect4_btf")]
#[test_attr(test_log::test)]
fn cgroup_storage(#[case] storage_map: &str, #[case] percpu_map: &str, #[case] prog: &str) {
    let missing = super::unsupported_map_names([
        (MapType::CgroupStorage, &["STORAGE", "STORAGE_LEGACY"][..]),
        (MapType::PerCpuCgroupStorage, &["PERCPU", "PERCPU_LEGACY"]),
    ]);
    let Some(mut bpf) = super::map_load_or_expect_unsupported(
        EbpfLoader::new().load(crate::CGROUP_STORAGE),
        &missing,
    ) else {
        return;
    };

    let _netns = NetNsGuard::new().unwrap();
    let root = Cgroup::root().unwrap();
    let cgroup = root.create_child(prog).unwrap();
    let cgroup_fd = cgroup.fd().unwrap();
    let cgroup_inode_id = cgroup_fd.metadata().expect("cgroup metadata").ino();

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
            .attach(cgroup_fd, CgroupAttachMode::Single)
            .unwrap_or_else(|err| panic!("attach {prog}: {err}"));
    }

    let cgroup = cgroup.into_cgroup();
    cgroup.write_pid(process::id()).unwrap();

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
