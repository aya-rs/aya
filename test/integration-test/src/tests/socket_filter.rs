use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{Array, MapData},
    programs::{ProgramError, ProgramType, ReusePortSocketFilter, SocketFilter, SocketFilterError},
    sys::is_program_supported,
    util::KernelVersion,
};
use integration_common::socket_filter::{
    PASS_HITS_INDEX, REUSEPORT_FIRST_LISTENER_INDEX, REUSEPORT_SECOND_LISTENER_INDEX,
    REUSEPORT_SELECT_FIRST_HITS_INDEX, REUSEPORT_SELECT_SECOND_HITS_INDEX, TRIM_DELTA_BYTES,
    TRIM_HITS_INDEX,
};
use libc::{EINVAL, ENOENT};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UnixDatagram},
    time::timeout,
};

use crate::utils::NetNsGuard;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_PAYLOAD: &[u8] = b"hello-world";
// Leave room for one extra byte so an unexpectedly long datagram is not
// truncated to the expected length.
const RECV_BUF_LEN: usize = TEST_PAYLOAD.len() + 1;

fn read_hits(hits: &Array<MapData, u64>, index: u32) -> u64 {
    hits.get(&index, 0).unwrap()
}

fn reuseport_detach_supported() -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    // `SO_DETACH_REUSEPORT_BPF` is handled starting in Linux 5.3:
    // https://github.com/torvalds/linux/blob/v5.3/net/core/sock.c#L1042-L1044
    if kernel_version < KernelVersion::new(5, 3, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, SO_DETACH_REUSEPORT_BPF requires 5.3"
        );
        return false;
    }

    true
}

fn reuseport_listener(port: u16) -> io::Result<TcpListener> {
    const LISTEN_BACKLOG: u32 = 1;

    // `SO_REUSEPORT` must be set before `bind(2)`. `tokio::net::TcpListener`
    // is already bound, so create the socket through `TcpSocket` first.
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(true)?;
    socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    socket.listen(LISTEN_BACKLOG)
}

fn reuseport_listeners() -> [TcpListener; 2] {
    let first = reuseport_listener(0).expect("failed to create first reuseport listener");
    let port = first
        .local_addr()
        .expect("failed to read first reuseport listener address")
        .port();
    let second = reuseport_listener(port).expect("failed to create second reuseport listener");
    [first, second]
}

async fn accept_from_either(first: &TcpListener, second: &TcpListener) -> i64 {
    // Keep these return values aligned with the indexes returned by the eBPF
    // reuseport selectors. `reuseport_listeners()` binds `first` before
    // `second`, and the kernel indexes reuseport sockets by group insertion
    // order, not by the socket used later for SO_ATTACH_REUSEPORT_EBPF:
    // - first socket becomes socks[0]:
    //   https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L233-L238
    // - later sockets are appended at socks[num_socks]:
    //   https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L124-L130
    timeout(ACCEPT_TIMEOUT, async {
        tokio::select! {
            result = first.accept() => {
                result.expect("failed to accept connection");
                REUSEPORT_FIRST_LISTENER_INDEX
            }
            result = second.accept() => {
                result.expect("failed to accept connection");
                REUSEPORT_SECOND_LISTENER_INDEX
            }
        }
    })
    .await
    .expect("timed out waiting for accept")
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

    SocketFilter::detach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert_eq!(
        read_hits(&path_hits, TRIM_HITS_INDEX),
        trim_hits_before_detach,
        "trim path ran after detach",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_attach_types_use_separate_slots() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    if !reuseport_detach_supported() {
        return;
    }

    // Aya's CI VM init may leave `lo` down; NetNsGuard brings it up.
    let _netns = NetNsGuard::new();
    let listener = reuseport_listener(0).expect("failed to create reuseport listener");

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();

    {
        let prog: &mut SocketFilter = ebpf
            .program_mut("pass_packets")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(&listener).unwrap();
    }

    // Attaching a regular socket filter must not populate the reuseport
    // selector slot.
    let err = ReusePortSocketFilter::detach(&listener).unwrap_err();
    assert_matches!(
        err,
        ProgramError::SocketFilterError(SocketFilterError::SetsockoptError {
            option: "SO_DETACH_REUSEPORT_BPF",
            io_error,
        }) if io_error.raw_os_error() == Some(ENOENT)
    );
    SocketFilter::detach(&listener).expect("regular socket filter should still be attached");

    {
        let prog: &mut ReusePortSocketFilter = ebpf
            .program_mut("select_first")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(&listener).unwrap();
    }

    // A TCP listener is awkward for a regular socket filter path assertion, so
    // only smoke-test that the reuseport selector actually runs.
    let _client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    timeout(ACCEPT_TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(
        read_hits(&path_hits, REUSEPORT_SELECT_FIRST_HITS_INDEX) > 0,
        "reuseport path did not run",
    );

    // Conversely, attaching a reuseport selector must not populate the
    // socket's regular filter slot.
    let err = SocketFilter::detach(&listener).unwrap_err();
    assert_matches!(
        err,
        ProgramError::SocketFilterError(SocketFilterError::SetsockoptError {
            option: "SO_DETACH_BPF",
            io_error,
        }) if io_error.raw_os_error() == Some(ENOENT)
    );
    // The reuseport selector should still be attached after the wrong detach
    // type above.
    ReusePortSocketFilter::detach(&listener).expect("reuseport selector should still be attached");

    {
        let prog: &mut SocketFilter = ebpf
            .program_mut("pass_packets")
            .unwrap()
            .try_into()
            .unwrap();
        prog.attach(&listener).unwrap();
    }
    {
        let prog: &mut ReusePortSocketFilter = ebpf
            .program_mut("select_first")
            .unwrap()
            .try_into()
            .unwrap();
        prog.attach(&listener).unwrap();
    }

    // Both slots can be populated on the same socket at the same time.
    ReusePortSocketFilter::detach(&listener).expect("failed to detach reuseport selector");
    SocketFilter::detach(&listener).expect("failed to detach regular socket filter");
}

#[test_log::test(tokio::test)]
async fn socket_filter_reuseport_selects_listener_and_detaches() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    if !reuseport_detach_supported() {
        return;
    }

    // Aya's CI VM init may leave `lo` down; NetNsGuard brings it up.
    let _netns = NetNsGuard::new();
    let [first, second] = reuseport_listeners();
    let addr = first.local_addr().unwrap();

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
    let prog: &mut ReusePortSocketFilter = ebpf
        .program_mut("select_second")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(&first).unwrap();

    let _client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        accept_from_either(&first, &second).await,
        REUSEPORT_SECOND_LISTENER_INDEX,
        "reuseport socket filter did not select the second listener",
    );
    assert!(
        read_hits(&path_hits, REUSEPORT_SELECT_SECOND_HITS_INDEX) > 0,
        "reuseport path did not run",
    );
    let hits_before_detach = read_hits(&path_hits, REUSEPORT_SELECT_SECOND_HITS_INDEX);

    // Reuseport detach is group-scoped: detaching through `second` clears the
    // selector for the whole group, including `first`.
    ReusePortSocketFilter::detach(&second).unwrap();

    let err = ReusePortSocketFilter::detach(&first).unwrap_err();
    assert_matches!(
        err,
        ProgramError::SocketFilterError(SocketFilterError::SetsockoptError {
            option: "SO_DETACH_REUSEPORT_BPF",
            io_error,
        }) if io_error.raw_os_error() == Some(ENOENT)
    );

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_from_either(&first, &second).await;
    assert_eq!(
        read_hits(&path_hits, REUSEPORT_SELECT_SECOND_HITS_INDEX),
        hits_before_detach,
        "reuseport path ran after detach",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_reuseport_stays_attached_after_ebpf_drop() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    if !reuseport_detach_supported() {
        return;
    }

    // Aya's CI VM init may leave `lo` down; NetNsGuard brings it up.
    let _netns = NetNsGuard::new();
    let [first, second] = reuseport_listeners();
    let addr = first.local_addr().unwrap();

    // Dropping `Ebpf` at the end of this scope releases local program FDs, but
    // the reuseport group slot owns the attachment and must keep it active.
    let path_hits: Array<_, u64> = {
        let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let prog: &mut ReusePortSocketFilter = ebpf
            .program_mut("select_second")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(&first).unwrap();
        path_hits
    };

    let _client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        accept_from_either(&first, &second).await,
        REUSEPORT_SECOND_LISTENER_INDEX,
        "dropping Ebpf detached the reuseport socket filter",
    );
    let hits_before_detach = read_hits(&path_hits, REUSEPORT_SELECT_SECOND_HITS_INDEX);
    assert!(
        hits_before_detach > 0,
        "reuseport path did not run after Ebpf drop",
    );

    ReusePortSocketFilter::detach(&first).unwrap();

    let _client = TcpStream::connect(addr).await.unwrap();
    accept_from_either(&first, &second).await;
    assert_eq!(
        read_hits(&path_hits, REUSEPORT_SELECT_SECOND_HITS_INDEX),
        hits_before_detach,
        "reuseport path ran after detach",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_reuseport_replacement_uses_latest_program() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    if !reuseport_detach_supported() {
        return;
    }

    // Aya's CI VM init may leave `lo` down; NetNsGuard brings it up.
    let _netns = NetNsGuard::new();
    let [first, second] = reuseport_listeners();
    let addr = first.local_addr().unwrap();

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();

    // Drop the mutable program reference before exercising the attachment. The
    // kernel slot, not a link handle, owns the attachment, so ending this scope
    // must not detach it.
    {
        let first_prog: &mut ReusePortSocketFilter = ebpf
            .program_mut("select_first")
            .unwrap()
            .try_into()
            .unwrap();
        first_prog.load().unwrap();
        first_prog.attach(&first).unwrap();
    }

    let _client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        accept_from_either(&first, &second).await,
        REUSEPORT_FIRST_LISTENER_INDEX,
        "first reuseport socket filter did not select the first listener",
    );
    let first_hits_before_replacement = read_hits(&path_hits, REUSEPORT_SELECT_FIRST_HITS_INDEX);
    assert!(
        first_hits_before_replacement > 0,
        "first reuseport path did not run",
    );

    // A second attach through the same reuseport group replaces `reuse->prog`;
    // it does not create a second attachment or change the socket indexes:
    // https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L684-L712
    {
        let second_prog: &mut ReusePortSocketFilter = ebpf
            .program_mut("select_second")
            .unwrap()
            .try_into()
            .unwrap();
        second_prog.load().unwrap();
        second_prog.attach(&first).unwrap();
    }

    let _client = TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        accept_from_either(&first, &second).await,
        REUSEPORT_SECOND_LISTENER_INDEX,
        "replacement reuseport socket filter did not select the second listener",
    );
    assert_eq!(
        read_hits(&path_hits, REUSEPORT_SELECT_FIRST_HITS_INDEX),
        first_hits_before_replacement,
        "replaced reuseport path ran after replacement",
    );
    assert!(
        read_hits(&path_hits, REUSEPORT_SELECT_SECOND_HITS_INDEX) > 0,
        "replacement reuseport path did not run",
    );

    ReusePortSocketFilter::detach(&second).unwrap();
}

#[test_log::test(tokio::test)]
async fn socket_filter_reuseport_errors_without_reuseport() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(4, 6, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, TCP SO_ATTACH_REUSEPORT_EBPF requires 4.6"
        );
        return;
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

    let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
    let prog: &mut ReusePortSocketFilter = ebpf
        .program_mut("select_second")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    // A bound listener without `SO_REUSEPORT` has no reuseport group; the
    // `SO_ATTACH_REUSEPORT_EBPF` path rejects that in `reuseport_attach_prog()`
    // with `-EINVAL`:
    // https://github.com/torvalds/linux/blob/v6.9/net/core/sock.c#L1396-L1405
    // https://github.com/torvalds/linux/blob/v6.9/net/core/sock_reuseport.c#L698-L700
    let err = prog.attach(&listener).unwrap_err();
    assert_matches!(
        err,
        ProgramError::SocketFilterError(SocketFilterError::SetsockoptError {
            option: "SO_ATTACH_REUSEPORT_EBPF",
            io_error,
        }) if io_error.raw_os_error() == Some(EINVAL)
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

    SocketFilter::detach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert_eq!(
        read_hits(&path_hits, TRIM_HITS_INDEX),
        trim_hits_before_detach,
        "trim path ran after detach",
    );
}

#[test_log::test(tokio::test)]
async fn socket_filter_stays_attached_after_ebpf_drop() {
    if !is_program_supported(ProgramType::SocketFilter).unwrap() {
        eprintln!("skipping test - socket_filter program not supported");
        return;
    }

    let (sender, receiver) = UnixDatagram::pair().unwrap();
    let path_hits: Array<_, u64> = {
        let mut ebpf = Ebpf::load(crate::SOCKET_FILTER).unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let prog: &mut SocketFilter = ebpf
            .program_mut("trim_packets")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(&receiver).unwrap();
        path_hits
    };

    send_and_assert(&sender, &receiver, TRIM_DELTA_BYTES as usize).await;
    let trim_hits_before_detach = read_hits(&path_hits, TRIM_HITS_INDEX);
    assert!(
        trim_hits_before_detach > 0,
        "dropping Ebpf detached the socket filter",
    );

    SocketFilter::detach(&receiver).unwrap();

    send_and_assert(&sender, &receiver, 0).await;
    assert_eq!(
        read_hits(&path_hits, TRIM_HITS_INDEX),
        trim_hits_before_detach,
        "trim path ran after detach",
    );
}
