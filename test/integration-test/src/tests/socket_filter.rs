use std::time::Duration;

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{Array, MapData},
    programs::{ProgramError, ProgramType, SocketFilter},
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
async fn socket_filter_detach_restores_unfiltered_delivery() {
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
    let link_id = prog.attach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert!(
        read_hits(&path_hits, PASS_HITS_INDEX) > 0,
        "pass path did not run",
    );
    let hits_before_detach = read_hits(&path_hits, PASS_HITS_INDEX);

    prog.detach(link_id).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert_eq!(
        read_hits(&path_hits, PASS_HITS_INDEX),
        hits_before_detach,
        "pass path ran after detach",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_duplicate_attach_keeps_existing_filter() {
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
    let hits_before_duplicate = read_hits(&path_hits, PASS_HITS_INDEX);
    assert!(hits_before_duplicate > 0, "pass path did not run");

    assert_matches!(prog.attach(&receiver), Err(ProgramError::AlreadyAttached));

    send_and_assert(&sender, &receiver, 0).await;
    assert!(
        read_hits(&path_hits, PASS_HITS_INDEX) > hits_before_duplicate,
        "duplicate attach detached the existing filter",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_owned_link_drop_restores_unfiltered_delivery() {
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
    let hits_before_attach = read_hits(&path_hits, TRIM_HITS_INDEX);

    let link_id = prog.attach(&receiver).unwrap();
    let link = prog.take_link(link_id).unwrap();

    send_and_assert(&sender, &receiver, TRIM_DELTA_BYTES as usize).await;
    assert!(
        read_hits(&path_hits, TRIM_HITS_INDEX) > hits_before_attach,
        "trim path did not run",
    );

    drop(link);

    send_and_assert(&sender, &receiver, 0).await;
}
