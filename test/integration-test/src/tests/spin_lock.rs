use std::{net::UdpSocket, time::Duration};

use aya::{
    EbpfLoader,
    maps::Array,
    programs::{Xdp, XdpFlags},
};
use integration_common::spin_lock::Counter;

use crate::utils::NetNsGuard;

#[test_log::test]
fn test_spin_lock() {
    let _netns = NetNsGuard::new();

    let mut ebpf = EbpfLoader::new().load(crate::SPIN_LOCK).unwrap();

    let prog: &mut Xdp = ebpf
        .program_mut("packet_counter")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("lo", XdpFlags::default()).unwrap();

    const PAYLOAD: &str = "hello counter";

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();

    let num_packets = 10;
    for _ in 0..num_packets {
        sock.send_to(PAYLOAD.as_bytes(), addr).unwrap();
    }

    // Read back the packets to ensure it went through the entire network stack,
    // including the XDP program.
    let mut buf = [0u8; PAYLOAD.len() + 1];
    for _ in 0..num_packets {
        let n = sock.recv(&mut buf).unwrap();
        assert_eq!(n, PAYLOAD.len());
        assert_eq!(&buf[..n], PAYLOAD.as_bytes());
    }

    let counter_map = ebpf.map("COUNTER").unwrap();
    let counter_map = Array::<_, Counter>::try_from(counter_map).unwrap();
    let Counter { count, .. } = counter_map.get(&0, 0).unwrap();
    assert_eq!(count, num_packets);
}
