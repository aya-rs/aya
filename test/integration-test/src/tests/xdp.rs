use std::{net::UdpSocket, os::fd::AsFd, time::Duration};

use aya::{
    maps::{Array, CpuMap},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use object::{Object, ObjectSection, ObjectSymbol, SymbolSection};

use crate::utils::NetNsGuard;

#[test]
fn prog_sections() {
    let obj_file = object::File::parse(crate::XDP_SEC).unwrap();

    assert!(has_symbol(&obj_file, "xdp", "xdp_plain"));
    assert!(has_symbol(&obj_file, "xdp.frags", "xdp_frags"));
    assert!(has_symbol(&obj_file, "xdp/cpumap", "xdp_cpumap"));
    assert!(has_symbol(&obj_file, "xdp/devmap", "xdp_devmap"));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/cpumap",
        "xdp_frags_cpumap"
    ));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/devmap",
        "xdp_frags_devmap"
    ));
}

fn has_symbol(obj_file: &object::File, sec_name: &str, sym_name: &str) -> bool {
    let sec = obj_file.section_by_name(sec_name).expect(sec_name);
    let sec = SymbolSection::Section(sec.index());
    obj_file
        .symbols()
        .any(|sym| sym.section() == sec && sym.name() == Ok(sym_name))
}

#[test]
fn map_load() {
    let bpf = Bpf::load(crate::XDP_SEC).unwrap();

    bpf.program("xdp_plain").unwrap();
    bpf.program("xdp_frags").unwrap();
    bpf.program("xdp_cpumap").unwrap();
    bpf.program("xdp_devmap").unwrap();
    bpf.program("xdp_frags_cpumap").unwrap();
    bpf.program("xdp_frags_devmap").unwrap();
}

#[test]
fn cpumap_chain() {
    let _netns = NetNsGuard::new();

    let mut bpf = Bpf::load(crate::REDIRECT).unwrap();

    // Load our cpumap and our canary map
    let mut cpus: CpuMap<_> = bpf.take_map("CPUS").unwrap().try_into().unwrap();
    let hits: Array<_, u32> = bpf.take_map("HITS").unwrap().try_into().unwrap();

    let xdp_chain_fd = {
        // Load the chained program to run on the target CPU
        let xdp: &mut Xdp = bpf
            .program_mut("redirect_cpu_chain")
            .unwrap()
            .try_into()
            .unwrap();
        xdp.load().unwrap();
        xdp.fd().unwrap()
    };
    cpus.set(0, 2048, Some(xdp_chain_fd.as_fd()), 0).unwrap();

    // Load the main program
    let xdp: &mut Xdp = bpf.program_mut("redirect_cpu").unwrap().try_into().unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    let sock = UdpSocket::bind("127.0.0.1:1777").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();
    sock.send_to(b"hello cpumap", "127.0.0.1:1777").unwrap();

    // Read back the packet to ensure it wenth through the entire network stack, including our two
    // probes.
    let mut buf = vec![0u8; 1000];
    let n = sock.recv(&mut buf).unwrap();

    assert_eq!(&buf[..n], b"hello cpumap");
    assert_eq!(hits.get(&0, 0).unwrap(), 1);
    assert_eq!(hits.get(&1, 0).unwrap(), 1);
}
