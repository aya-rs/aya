use std::{net::UdpSocket, num::NonZeroU32, time::Duration};

use aya::{
    Ebpf,
    maps::{Array, CpuMap, XskMap},
    programs::{Xdp, XdpFlags},
    util::KernelVersion,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolSection};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use crate::utils::{NetNsGuard, PeerNsGuard};

// Sanity-check the veth + PeerNsGuard plumbing without any BPF programs.
#[test_log::test]
fn veth_connectivity() {
    // peer must be declared after netns so it drops first (see PeerNsGuard docs).
    let netns = NetNsGuard::new();
    let peer = PeerNsGuard::new(&netns);

    let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::IFACE_ADDR)).unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    peer.run(|| {
        let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::PEER_ADDR)).unwrap();
        sock.send_to(b"veth ok", addr).unwrap();
    });

    let mut buf = [0u8; 16];
    let n = sock.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"veth ok");
}

#[test_log::test]
#[expect(
    clippy::big_endian_bytes,
    reason = "packet headers are encoded in network byte order"
)]
fn af_xdp() {
    // peer must be declared after netns so it drops first (see PeerNsGuard docs).
    let netns = NetNsGuard::new();
    let peer = PeerNsGuard::new(&netns);

    let mut bpf = Ebpf::load(crate::REDIRECT).unwrap();
    let mut socks: XskMap<_> = bpf.take_map("SOCKS").unwrap().try_into().unwrap();

    let xdp: &mut Xdp = bpf
        .program_mut("redirect_sock")
        .unwrap()
        .try_into()
        .unwrap();
    xdp.load().unwrap();
    xdp.attach(NetNsGuard::IFACE, XdpFlags::default()).unwrap();

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
    iface.from_name(c"veth0").unwrap();
    let sock = match Socket::with_shared(&iface, &umem) {
        Ok(sock) => sock,
        Err(err) => {
            if err.get_raw() == libc::ENOPROTOOPT {
                eprintln!("skipping test - AF_XDP sockets not available: {err}");
                return;
            }
            panic!("failed to create AF_XDP socket: {err} {}", err.get_raw());
        }
    };

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

    let dst = format!("{}:1777", NetNsGuard::IFACE_ADDR);
    let port = peer.run(|| {
        let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::PEER_ADDR)).unwrap();
        let port = sock.local_addr().unwrap().port();
        sock.send_to(b"hello AF_XDP", &dst).unwrap();
        port
    });

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
    let ports = &udp[..4];
    let (src, dst_port) = ports.split_at(2);
    assert_eq!(src, port.to_be_bytes().as_slice()); // Source
    assert_eq!(dst_port, 1777u16.to_be_bytes().as_slice()); // Dest
    assert_eq!(payload, b"hello AF_XDP");

    assert_eq!(rx.available(), 1);
    // Removes socket from map, no more packets will be redirected.
    socks.unset(0).unwrap();
    assert_eq!(rx.available(), 1);
    peer.run(|| {
        let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::PEER_ADDR)).unwrap();
        sock.send_to(b"hello AF_XDP", &dst).unwrap();
    });
    assert_eq!(rx.available(), 1);
    // Adds socket to map again, packets will be redirected again.
    socks.set(0, rx.as_raw_fd(), 0).unwrap();
    peer.run(|| {
        let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::PEER_ADDR)).unwrap();
        sock.send_to(b"hello AF_XDP", &dst).unwrap();
    });
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
fn ensure_symbol(obj_file: &object::File<'_>, sec_name: &str, sym_name: &str) {
    let sec = obj_file.section_by_name(sec_name).unwrap_or_else(|| {
        let secs = obj_file
            .sections()
            .filter_map(|sec| sec.name().ok().map(ToOwned::to_owned))
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
    // peer must be declared after netns so it drops first (see PeerNsGuard docs).
    let netns = NetNsGuard::new();
    let peer = PeerNsGuard::new(&netns);

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

    // While veth supports native XDP attachment from 5.9, cpumap chaining does
    // not reliably deliver packets through veth on older kernels (confirmed
    // failing on 5.10). Gate at 6.1 which is the oldest CI-tested kernel where
    // this works end-to-end.
    if KernelVersion::current().unwrap() < KernelVersion::new(6, 1, 0) {
        eprintln!("skipping test - cpumap chaining on veth unreliable on kernel < 6.1");
        return;
    }
    xdp.attach(NetNsGuard::IFACE, XdpFlags::default()).unwrap();

    const PAYLOAD: &str = "hello cpumap";

    let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::IFACE_ADDR)).unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    peer.run(|| {
        let sock = UdpSocket::bind(format!("{}:0", NetNsGuard::PEER_ADDR)).unwrap();
        sock.send_to(PAYLOAD.as_bytes(), addr).unwrap();
    });

    // Read back the packet to ensure it went through the entire network stack, including our two
    // probes.
    let mut buf = [0u8; PAYLOAD.len() + 1];
    let n = sock.recv(&mut buf).unwrap();

    assert_eq!(&buf[..n], PAYLOAD.as_bytes());
    assert_eq!(hits.get(&0, 0).unwrap(), 1);
    assert_eq!(hits.get(&1, 0).unwrap(), 1);
}
