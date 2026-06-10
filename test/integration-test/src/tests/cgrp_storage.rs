use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    maps::{CgrpStorage, MapError, MapType},
    programs::{BtfTracePoint, ProgramType},
    sys::{is_map_supported, is_program_supported},
    test_helpers::{Cgroup, is_cgroup2},
};
use integration_common::local_storage::SENTINEL;
use test_log::test;

#[test]
fn cgrp_storage() {
    if !is_map_supported(MapType::CgrpStorage).unwrap() {
        eprintln!("skipping test - cgroup storage maps not supported");
        return;
    }

    if !is_program_supported(ProgramType::Tracing).unwrap() {
        eprintln!("skipping test - tracing programs not supported");
        return;
    }

    if !is_cgroup2() {
        eprintln!("skipping test - /sys/fs/cgroup is not cgroup2");
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf: Ebpf = Ebpf::load(crate::CGRP_STORAGE).unwrap();

    let prog: &mut BtfTracePoint = bpf
        .program_mut("cgrp_storage_test")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load("cgroup_mkdir", &btf).unwrap();
    prog.attach().unwrap();

    // Creating a cgroup fires `cgroup_mkdir`, populating its storage.
    let root = Cgroup::root();
    let cgroup = root.create_child("aya-test-cgrp-storage").unwrap();
    let cgroup_fd = cgroup.fd().unwrap();

    let mut storage =
        CgrpStorage::<_, u64>::try_from(bpf.map_mut("CGRP_STORAGE").unwrap()).unwrap();
    assert_matches!(storage.get(&cgroup_fd, 0), Ok(value) => {
        assert_eq!(value, SENTINEL);
    });
    storage.remove(&cgroup_fd).unwrap();
    assert_matches!(storage.get(&cgroup_fd, 0), Err(MapError::KeyNotFound));
}
