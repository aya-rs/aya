use std::fs::remove_file;

use aya::{
    maps::SkStorage,
    programs::{CgroupAttachMode, CgroupSockAddr, CgroupSockAddrAttachType},
};
use test_log::test;

use crate::utils::Cgroup;

#[test]
fn cgroup_sock_addr_from_pin_attach() {
    // Test that CgroupSockAddr::from_pin() correctly sets expected_attach_type,
    // so that attach() does not panic.
    let mut ebpf = aya::EbpfLoader::new().load(crate::SK_STORAGE).unwrap();

    let storage = ebpf.take_map("SOCKET_STORAGE").unwrap();
    let _storage =
        SkStorage::<_, integration_common::sk_storage::Value>::try_from(storage).unwrap();

    let prog = ebpf
        .program_mut("sk_storage_connect4")
        .unwrap()
        .try_into()
        .unwrap();

    let prog: &mut CgroupSockAddr = prog;
    prog.load().unwrap();

    // Pin the program to bpffs
    let pin_path = "/sys/fs/bpf/aya-test-cgroup-sock-addr-from-pin";
    remove_file(pin_path).ok();
    prog.pin(pin_path).unwrap();

    // Reload from pinned path via from_pin() - this is the critical path.
    // Before the fix, expected_attach_type was not set in from_pin(),
    // causing attach() to panic with unwrap on None.
    let mut prog = CgroupSockAddr::from_pin(pin_path, CgroupSockAddrAttachType::Connect4).unwrap();

    let root = Cgroup::root();
    let cgroup = root.create_child("aya-test-cgroup-sock-addr-from-pin");
    let cgroup_fd = cgroup.fd();

    // This attach() would panic if expected_attach_type was not set by from_pin().
    let _link_id = prog.attach(cgroup_fd, CgroupAttachMode::Single).unwrap();

    // Clean up
    drop(cgroup);
    remove_file(pin_path).ok();
}
