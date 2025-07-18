use std::{net::UdpSocket, num::NonZeroU32, time::Duration};

use aya::{
    Ebpf,
    maps::{Array, CpuMap, XskMap},
    programs::{Xdp, XdpFlags},
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolSection};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use crate::utils::NetNsGuard;

#[test_log::test]
fn af_xdp() {
    let _netns = NetNsGuard::new();

    let mut bpf = Ebpf::load(crate::REDIRECT).unwrap();
    let mut socks: XskMap<_> = bpf.take_map("SOCKS").unwrap().try_into().unwrap();

    let xdp: &mut Xdp = bpf
        .program_mut("redirect_sock")
        .unwrap()
        .try_into()
        .unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    const SIZE: usize = 2 * 4096;

    // So this needs to be page aligned. Pages are 4k on all mainstream architectures except for
    // Apple Silicon which uses 16k pages. So let's align on that for tests to run natively there.
    #[repr(C, align(16384))]
    struct PageAligned([u8; SIZE]);

    let mut alloc = Box::new(PageAligned([0; SIZE]));
    let umem = {
        let PageAligned(mem) = alloc.as_mut();
        let mem = mem.as_mut().into();
        // Safety: we cannot access `mem` further down the line because it falls out of scope.
        unsafe { Umem::new(UmemConfig::default(), mem).unwrap() }
    };

    let mut iface = IfInfo::invalid();
    iface.from_name(c"lo").unwrap();
    let sock = Socket::with_shared(&iface, &umem).unwrap();

    let mut fq_cq = umem.fq_cq(&sock).unwrap(); // Fill Queue / Completion Queue

    let cfg = SocketConfig {
        rx_size: NonZeroU32::new(32),
        ..Default::default()
    };
    let rxtx = umem.rx_tx(&sock, &cfg).unwrap(); // RX + TX Queues
    let mut rx = rxtx.map_rx().unwrap();

    umem.bind(&rxtx).unwrap();

    socks.set(0, rx.as_raw_fd(), 0).unwrap();

    let frame = umem.frame(BufIdx(0)).unwrap();
    let frame1 = umem.frame(BufIdx(1)).unwrap();

    // Produce two frames to be filled by the kernel
    let mut writer = fq_cq.fill(2);
    writer.insert_once(frame.offset);
    writer.insert_once(frame1.offset);
    writer.commit();

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    sock.send_to(b"hello AF_XDP", "127.0.0.1:1777").unwrap();

    assert_eq!(rx.available(), 1);
    let desc = rx.receive(1).read().unwrap();
    let buf = unsafe {
        &frame.addr.as_ref()[desc.addr as usize..(desc.addr as usize + desc.len as usize)]
    };

    let (eth, buf) = buf.split_at(14);
    assert_eq!(eth[12..14], [0x08, 0x00]); // IP
    let (ip, buf) = buf.split_at(20);
    assert_eq!(ip[9], 17); // UDP
    let (udp, payload) = buf.split_at(8);
    assert_eq!(&udp[0..2], port.to_be_bytes().as_slice()); // Source
    assert_eq!(&udp[2..4], 1777u16.to_be_bytes().as_slice()); // Dest
    assert_eq!(payload, b"hello AF_XDP");

    assert_eq!(rx.available(), 1);
    // Removes socket from map, no more packets will be redirected.
    socks.unset(0).unwrap();
    assert_eq!(rx.available(), 1);
    sock.send_to(b"hello AF_XDP", "127.0.0.1:1777").unwrap();
    assert_eq!(rx.available(), 1);
    // Adds socket to map again, packets will be redirected again.
    socks.set(0, rx.as_raw_fd(), 0).unwrap();
    sock.send_to(b"hello AF_XDP", "127.0.0.1:1777").unwrap();
    assert_eq!(rx.available(), 2);
}

#[test_log::test]
fn prog_sections() {
    let obj_file = object::File::parse(crate::XDP_SEC).unwrap();

    ensure_symbol(&obj_file, "xdp", "xdp_plain");
    ensure_symbol(&obj_file, "xdp.frags", "xdp_frags");
    ensure_symbol(&obj_file, "xdp/cpumap", "xdp_cpumap");
    ensure_symbol(&obj_file, "xdp/devmap", "xdp_devmap");
    ensure_symbol(&obj_file, "xdp.frags/cpumap", "xdp_frags_cpumap");
    ensure_symbol(&obj_file, "xdp.frags/devmap", "xdp_frags_devmap");
}

#[track_caller]
fn ensure_symbol(obj_file: &object::File, sec_name: &str, sym_name: &str) {
    let sec = obj_file.section_by_name(sec_name).unwrap_or_else(|| {
        let secs = obj_file
            .sections()
            .flat_map(|sec| sec.name().ok().map(|name| name.to_owned()))
            .collect::<Vec<_>>();
        panic!("section {sec_name} not found. available sections: {secs:?}");
    });
    let sec = SymbolSection::Section(sec.index());

    let syms = obj_file
        .symbols()
        .filter(|sym| sym.section() == sec)
        .filter_map(|sym| sym.name().ok())
        .collect::<Vec<_>>();
    assert!(
        syms.contains(&sym_name),
        "symbol not found. available symbols in section: {syms:?}"
    );
}

#[test_log::test]
fn map_load() {
    let bpf = Ebpf::load(crate::XDP_SEC).unwrap();

    bpf.program("xdp_plain").unwrap();
    bpf.program("xdp_frags").unwrap();
    bpf.program("xdp_cpumap").unwrap();
    bpf.program("xdp_devmap").unwrap();
    bpf.program("xdp_frags_cpumap").unwrap();
    bpf.program("xdp_frags_devmap").unwrap();
}

#[test_log::test]
fn cpumap_chain() {
    let _netns = NetNsGuard::new();

    let mut bpf = Ebpf::load(crate::REDIRECT).unwrap();

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
    cpus.set(0, 2048, Some(xdp_chain_fd), 0).unwrap();

    // Load the main program
    let xdp: &mut Xdp = bpf.program_mut("redirect_cpu").unwrap().try_into().unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    const PAYLOAD: &str = "hello cpumap";

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    sock.send_to(PAYLOAD.as_bytes(), addr).unwrap();

    // Read back the packet to ensure it went through the entire network stack, including our two
    // probes.
    let mut buf = [0u8; PAYLOAD.len() + 1];
    let n = sock.recv(&mut buf).unwrap();

    assert_eq!(&buf[..n], PAYLOAD.as_bytes());
    assert_eq!(hits.get(&0, 0).unwrap(), 1);
    assert_eq!(hits.get(&1, 0).unwrap(), 1);
}
