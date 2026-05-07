use std::time::Duration;

use aya::{
    Ebpf,
    maps::{Array, MapData},
    programs::{ProgramType, SocketFilter},
    sys::is_program_supported,
};
use integration_common::socket_filter::{PASS_HITS_INDEX, TRIM_DELTA_BYTES, TRIM_HITS_INDEX};
use tokio::{net::UnixDatagram, time::timeout};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_PAYLOAD: &[u8] = b"hello-world";
// Leave room for one extra byte so an unexpectedly long datagram is not
// truncated to the expected length.
const RECV_BUF_LEN: usize = TEST_PAYLOAD.len() + 1;

fn read_hits(hits: &Array<MapData, u64>, index: u32) -> u64 {
    hits.get(&index, 0).unwrap()
}

async fn send_and_assert(sender: &UnixDatagram, receiver: &UnixDatagram, trim_bytes: usize) {
    sender
        .send(TEST_PAYLOAD)
        .await
        .expect("failed to send datagram");

    let mut buf = [0u8; RECV_BUF_LEN];
    let len = timeout(IO_TIMEOUT, receiver.recv(&mut buf))
        .await
        .expect("timed out waiting for datagram")
        .expect("failed to receive datagram");
    let expected_len = TEST_PAYLOAD.len().saturating_sub(trim_bytes);
    let expected = &TEST_PAYLOAD[..expected_len];
    assert_eq!(&buf[..len], expected);
}

#[test_log::test(tokio::test)]
async fn socket_filter_program_can_pass_packets() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let (sender, receiver) = UnixDatagram::pair().unwrap();

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
    let prog: &mut SocketFilter = ebpf
        .program_mut("pass_packets")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert!(
        read_hits(&path_hits, PASS_HITS_INDEX) > 0,
        "pass path did not run",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_program_can_trim_packets_and_detach() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let (sender, receiver) = UnixDatagram::pair().unwrap();

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
    let prog: &mut SocketFilter = ebpf
        .program_mut("trim_packets")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, TRIM_DELTA_BYTES as usize).await;
    let trim_hits_before_detach = read_hits(&path_hits, TRIM_HITS_INDEX);
    assert!(trim_hits_before_detach > 0, "trim path did not run");

    prog.detach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert_eq!(
        read_hits(&path_hits, TRIM_HITS_INDEX),
        trim_hits_before_detach,
        "trim path ran after detach",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_replacement_stays_attached_until_explicit_detach() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let (sender, receiver) = UnixDatagram::pair().unwrap();

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();

    let pass_prog: &mut SocketFilter = ebpf
        .program_mut("pass_packets")
        .unwrap()
        .try_into()
        .unwrap();
    pass_prog.load().unwrap();
    pass_prog.attach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert!(
        read_hits(&path_hits, PASS_HITS_INDEX) > 0,
        "pass path did not run",
    );
    let pass_hits_before_replacement = read_hits(&path_hits, PASS_HITS_INDEX);

    let trim_prog: &mut SocketFilter = ebpf
        .program_mut("trim_packets")
        .unwrap()
        .try_into()
        .unwrap();
    trim_prog.load().unwrap();
    trim_prog.attach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, TRIM_DELTA_BYTES as usize).await;
    let trim_hits_before_unload = read_hits(&path_hits, TRIM_HITS_INDEX);
    assert!(trim_hits_before_unload > 0, "trim path did not run");
    // Socket filters use a single per-socket slot, so the second attach
    // replaces the pass filter instead of running both filters.
    assert_eq!(
        read_hits(&path_hits, PASS_HITS_INDEX),
        pass_hits_before_replacement,
        "pass path ran after replacement",
    );

    let pass_prog: &mut SocketFilter = ebpf
        .program_mut("pass_packets")
        .unwrap()
        .try_into()
        .unwrap();
    pass_prog.unload().unwrap();

    send_and_assert(&sender, &receiver, TRIM_DELTA_BYTES as usize).await;
    assert!(
        read_hits(&path_hits, TRIM_HITS_INDEX) > trim_hits_before_unload,
        "unloading the replaced program detached the replacement filter",
    );
    let trim_hits_before_detach = read_hits(&path_hits, TRIM_HITS_INDEX);

    let trim_prog: &mut SocketFilter = ebpf
        .program_mut("trim_packets")
        .unwrap()
        .try_into()
        .unwrap();
    trim_prog.detach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert_eq!(
        read_hits(&path_hits, TRIM_HITS_INDEX),
        trim_hits_before_detach,
        "trim path ran after detach",
    );
}
