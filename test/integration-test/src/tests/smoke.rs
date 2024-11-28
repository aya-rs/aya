use std::net::UdpSocket;

use aya::{
    maps::Array, programs::{Extension, TracePoint, Xdp, XdpFlags}, util::KernelVersion, Ebpf, EbpfLoader
};
use test_log::test;

use crate::utils::NetNsGuard;

#[test]
fn xdp() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 18, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, support for BPF_F_XDP_HAS_FRAGS was added in 5.18.0; see https://github.com/torvalds/linux/commit/c2f2cdb");
        return;
    }

    let _netns = NetNsGuard::new();

    let mut bpf = Ebpf::load(crate::PASS).unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("lo", XdpFlags::default()).unwrap();
}

#[test]
fn two_progs() {
    let mut bpf = Ebpf::load(crate::TWO_PROGS).unwrap();

    let prog_one: &mut TracePoint = bpf
        .program_mut("test_tracepoint_one")
        .unwrap()
        .try_into()
        .unwrap();

    prog_one.load().unwrap();
    prog_one.attach("sched", "sched_switch").unwrap();

    let prog_two: &mut TracePoint = bpf
        .program_mut("test_tracepoint_two")
        .unwrap()
        .try_into()
        .unwrap();
    prog_two.load().unwrap();
    prog_two.attach("sched", "sched_switch").unwrap();
}

#[test]
fn extension() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 9, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, XDP uses netlink");
        return;
    }

    let _netns = NetNsGuard::new();

    let mut bpf = Ebpf::load(crate::MAIN).unwrap();
    let pass: &mut Xdp = bpf.program_mut("xdp_pass").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();

    let mut bpf = EbpfLoader::new()
        .extension("xdp_drop")
        .load(crate::EXT)
        .unwrap();
    let drop_: &mut Extension = bpf.program_mut("xdp_drop").unwrap().try_into().unwrap();
    drop_
        .load(pass.fd().unwrap().try_clone().unwrap(), "xdp_pass")
        .unwrap();
}

#[test]
fn map_set() {
    let _netns = NetNsGuard::new();

    let mut bpf = Ebpf::load(crate::MAP_TEST).unwrap();
    let dispatcher: &mut Xdp = bpf
        .program_mut("foo_map_insert")
        .unwrap()
        .try_into()
        .unwrap();
    dispatcher.load().unwrap();
    dispatcher.attach("lo", XdpFlags::default()).unwrap();
    let map: Array<&aya::maps::MapData, u32> = Array::try_from(bpf.map("FOO").unwrap()).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect("127.0.0.1:12345").unwrap();
    socket.send(&[0; 1]).unwrap();
    if let Ok(val) = map.get(&0, 0) {
        assert_eq!(val, 1234);
    } else {
        panic!("Key not found");
    }
}