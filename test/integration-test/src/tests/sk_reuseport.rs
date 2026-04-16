use std::{
    io,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    time::Duration,
};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{Array, MapData, ReusePortSockArray},
    programs::{ProgramError, SkReuseport, SkReuseportError},
    util::KernelVersion,
};
use futures::future::select_all;
use integration_common::sk_reuseport::{
    CLEAR_FALLBACK_HITS_INDEX, MIGRATE_HITS_INDEX, MIGRATE_SOCKET_INDEX, SELECT_HITS_INDEX,
    SELECT_SOCKET_INDEX,
};
use libc::{EINVAL, ENOENT};
use test_case::test_case;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener as TokioTcpListener, TcpSocket, TcpStream as TokioTcpStream},
    time::{sleep, timeout},
};

use crate::utils::NetNsGuard;

const RETRY_DURATION: Duration = Duration::from_millis(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn reuseport_listener(port: u16) -> io::Result<TokioTcpListener> {
    // `SO_REUSEPORT` must be set before `bind(2)`. The kernel only adds a
    // socket to a reuseport group during bind:
    // - Bind requires both the existing and new sockets to have
    //   `SO_REUSEPORT` set; if either side lacks it, bind fails with
    //   `EADDRINUSE`.
    // - Setting `SO_REUSEPORT` after bind is silently ignored; the socket is
    //   not added to any reuseport group.
    // `tokio::net::TcpListener` is already past the pre-bind configuration
    // stage, so the test creates the listener through `TcpSocket` instead.
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(true)?;
    socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    socket.listen(1024)
}

fn reuseport_listeners<const N: usize>() -> [TokioTcpListener; N] {
    let first = reuseport_listener(0).expect("failed to create first reuseport listener");
    let port = first
        .local_addr()
        .expect("failed to read first reuseport listener address")
        .port();
    let mut first = Some(first);
    std::array::from_fn(|index| {
        if index == 0 {
            first.take().expect("first reuseport listener should exist")
        } else {
            reuseport_listener(port).expect("failed to create reuseport listener")
        }
    })
}

fn read_hits(hits: &Array<MapData, u64>, index: u32) -> u64 {
    hits.get(&index, 0).unwrap()
}

async fn wait_for_accept_tokio(listeners: &[&TokioTcpListener]) -> (usize, TokioTcpStream) {
    let futs: Vec<_> = listeners
        .iter()
        .map(|listener| Box::pin(listener.accept()))
        .collect();
    let (result, idx, _) = timeout(ACCEPT_TIMEOUT, select_all(futs))
        .await
        .expect("timed out waiting for accept");
    let (stream, _) = result.expect("failed to accept connection");
    (idx, stream)
}

// Reuseport migration inserts connections into the target listener's accept
// queue, but the two migration paths differ in whether they wake the listener:
//
// - Half-open (SYN_RECV) connections migrated via reqsk_timer_handler [1]
//   complete the handshake on the new listener, so the client's ACK triggers
//   sk_data_ready() naturally.
//
// - Fully established connections migrated via inet_csk_listen_stop [2] are
//   inserted directly into the accept queue [3] without calling
//   sk_data_ready(), so epoll never sees a READABLE event.
//
// Tokio's accept relies on epoll, so it hangs for the established case.
// Blocking poll(2)/select(2) would also hang for the same reason.
// Non-blocking accept(2) checks the queue directly, bypassing readiness notification.
//
// [1] https://github.com/torvalds/linux/blob/v6.15/net/ipv4/inet_connection_sock.c#L1070-L1100
// [2] https://github.com/torvalds/linux/blob/v6.15/net/ipv4/inet_connection_sock.c#L1484-L1554
// [3] https://github.com/torvalds/linux/blob/v6.15/net/ipv4/inet_connection_sock.c#L1513
async fn wait_for_accept_polling(listeners: [&StdTcpListener; 2]) -> (usize, TokioTcpStream) {
    timeout(ACCEPT_TIMEOUT, async {
        loop {
            for (idx, listener) in listeners.iter().enumerate() {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(true)
                            .expect("failed to set accepted stream nonblocking");
                        let stream = TokioTcpStream::from_std(stream)
                            .expect("failed to convert accepted stream to tokio");
                        return (idx, stream);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                    Err(err) => panic!("failed to accept connection: {err}"),
                }
            }

            sleep(RETRY_DURATION).await;
        }
    })
    .await
    .expect("timed out waiting for accepted connection")
}

async fn connect(addr: SocketAddr) -> io::Result<TokioTcpStream> {
    TokioTcpStream::connect(addr).await
}

async fn assert_connection_works(mut client: TokioTcpStream, mut server: TokioTcpStream) {
    timeout(IO_TIMEOUT, async move {
        client
            .write_all(b"aya")
            .await
            .expect("failed to write test payload");
        drop(client);
        let mut buf = Vec::new();
        server
            .read_to_end(&mut buf)
            .await
            .expect("failed to read test payload to EOF");
        assert_eq!(buf, b"aya");
    })
    .await
    .expect("timed out waiting for connection I/O");
}

// `NetNsGuard` switches the current thread into a dedicated network namespace,
// so these async tests must stay on a single runtime thread.
#[test_case("legacy", "socket_map", "select_socket"; "legacy")]
#[test_case("btf", "socket_map_btf", "select_socket_btf"; "btf")]
#[test_log::test(tokio::test)]
async fn sk_reuseport_selects_expected_listener(label: &str, socket_map: &str, select_prog: &str) {
    let _netns = NetNsGuard::new();

    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let mut socket_array: ReusePortSockArray<_> =
        ebpf.take_map(socket_map).unwrap().try_into().unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
    let [first, second, third] = reuseport_listeners();
    let addr = first.local_addr().unwrap();

    for (index, listener) in [&first, &second, &third].into_iter().enumerate() {
        socket_array.set(index as u32, listener, 0).unwrap();
    }

    {
        // Limit the mutable borrow of `ebpf` from `program_mut()` to this block.
        let prog: &mut SkReuseport = ebpf.program_mut(select_prog).unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.attach(&first).unwrap();
    }

    let client = connect(addr).await.unwrap();
    let (accepted_idx, server) = wait_for_accept_tokio(&[&first, &second, &third]).await;
    assert_eq!(
        accepted_idx, SELECT_SOCKET_INDEX as usize,
        "{label}: connection should be steered to listener A",
    );

    // Confirm that the BPF select path ran, not just the kernel's default
    // SO_REUSEPORT selection logic landing on listener A by chance.
    assert!(
        read_hits(&path_hits, SELECT_HITS_INDEX) > 0,
        "{label}: select path did not run",
    );
    assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
    assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
    assert_connection_works(client, server).await;

    let prog: &mut SkReuseport = ebpf.program_mut(select_prog).unwrap().try_into().unwrap();

    // `SkReuseport` attachments are group-scoped: detaching through any socket in
    // the reuseport group removes the program from the whole group, even if that
    // socket was not used for attach, so a second detach through listener A yields
    // ENOENT.
    prog.detach(&second).unwrap();

    let err = prog.detach(&first).unwrap_err();
    assert_matches!(
        err,
        ProgramError::SkReuseportError(SkReuseportError::SetsockoptError {
            option: "SO_DETACH_REUSEPORT_BPF",
            io_error,
        }) if io_error.raw_os_error() == Some(ENOENT),
        "unexpected error for {}",
        label,
    );
}

#[test_case("legacy", "socket_map", "select_socket_after_clear"; "legacy")]
#[test_case("btf", "socket_map_btf", "select_socket_after_clear_btf"; "btf")]
#[test_log::test(tokio::test)]
async fn sk_reuseport_clear_index_changes_selection(
    label: &str,
    socket_map: &str,
    clear_prog: &str,
) {
    let _netns = NetNsGuard::new();

    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let mut socket_array: ReusePortSockArray<_> =
        ebpf.take_map(socket_map).unwrap().try_into().unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
    let [first, second, third] = reuseport_listeners();
    let addr = first.local_addr().unwrap();

    for (index, listener) in [&first, &second, &third].into_iter().enumerate() {
        socket_array.set(index as u32, listener, 0).unwrap();
    }

    {
        // Limit the mutable borrow of `ebpf` from `program_mut()` to this block.
        let prog: &mut SkReuseport = ebpf.program_mut(clear_prog).unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.attach(&first).unwrap();
    }

    let first_client = connect(addr).await.unwrap();
    let (first_accepted_idx, first_server) =
        wait_for_accept_tokio(&[&first, &second, &third]).await;
    assert_eq!(
        first_accepted_idx, SELECT_SOCKET_INDEX as usize,
        "{label}: before clearing key 0, the program should steer to listener A",
    );
    assert!(
        read_hits(&path_hits, SELECT_HITS_INDEX) > 0,
        "{label}: select path did not run before clear",
    );
    assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
    assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
    assert_connection_works(first_client, first_server).await;

    socket_array.clear_index(&SELECT_SOCKET_INDEX).unwrap();

    let second_client = connect(addr).await.unwrap();
    let (second_accepted_idx, second_server) =
        wait_for_accept_tokio(&[&first, &second, &third]).await;
    assert_eq!(
        second_accepted_idx, MIGRATE_SOCKET_INDEX as usize,
        "{label}: after clearing key 0, the program should fall back to listener C",
    );
    assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
    // Confirm that the test program observed the missing primary key and
    // explicitly selected listener C, rather than relying on the kernel's
    // default SO_REUSEPORT selection logic.
    assert!(
        read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX) > 0,
        "{label}: clear fallback path did not run",
    );
    assert_connection_works(second_client, second_server).await;
}

#[test_case("legacy", "select_socket"; "legacy")]
#[test_case("btf", "select_socket_btf"; "btf")]
#[test_log::test(tokio::test)]
async fn sk_reuseport_detaches_after_unload(label: &str, select_prog: &str) {
    let _netns = NetNsGuard::new();

    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let [first, second] = reuseport_listeners();

    let prog: &mut SkReuseport = ebpf.program_mut(select_prog).unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach(&first).unwrap();
    prog.unload().unwrap();

    // `SO_DETACH_REUSEPORT_BPF` identifies the group solely from the
    // socket, so detaching should still succeed after the local program FD
    // has been unloaded.
    prog.detach(&second).unwrap();

    let err = prog.detach(&first).unwrap_err();
    assert_matches!(
        err,
        ProgramError::SkReuseportError(SkReuseportError::SetsockoptError {
            option: "SO_DETACH_REUSEPORT_BPF",
            io_error,
        }) if io_error.raw_os_error() == Some(ENOENT),
        "unexpected error for {}",
        label,
    );
}

#[test_case("legacy", "socket_map", "select_or_migrate_socket"; "legacy")]
#[test_case("btf", "socket_map_btf", "select_or_migrate_socket_btf"; "btf")]
#[test_log::test(tokio::test)]
async fn sk_reuseport_migrates_to_expected_listener(
    label: &str,
    socket_map: &str,
    migrate_prog: &str,
) {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 14, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, sk_reuseport/migrate requires 5.14");
        return;
    }

    let _netns = NetNsGuard::new();
    match std::fs::write("/proc/sys/net/ipv4/tcp_migrate_req", "1") {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            eprintln!("skipping test - tcp_migrate_req not configurable in test netns: {err}");
            return;
        }
        Err(err) => panic!("unexpected error configuring tcp_migrate_req: {err}"),
    }

    let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
    let mut socket_array: ReusePortSockArray<_> =
        ebpf.take_map(socket_map).unwrap().try_into().unwrap();
    let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
    let [listener_a, listener_b, listener_c] = reuseport_listeners();

    for (index, listener) in [&listener_a, &listener_b, &listener_c]
        .into_iter()
        .enumerate()
    {
        socket_array.set(index as u32, listener, 0).unwrap();
    }

    let prog: &mut SkReuseport = ebpf.program_mut(migrate_prog).unwrap().try_into().unwrap();
    match prog.load() {
        Ok(()) => {}
        Err(ProgramError::LoadError { io_error, .. })
            if io_error.raw_os_error() == Some(EINVAL) =>
        {
            eprintln!(
                "skipping {label} test - kernel rejected BPF_SK_REUSEPORT_SELECT_OR_MIGRATE at load"
            );
            return;
        }
        Err(err) => {
            panic!("unexpected error loading sk_reuseport/migrate program for {label}: {err}")
        }
    }

    {
        // Limit the mutable borrow of `ebpf` from `program_mut()` to this block.
        let prog: &mut SkReuseport = ebpf.program_mut(migrate_prog).unwrap().try_into().unwrap();
        prog.attach(&listener_a).unwrap();
    }

    let addr = listener_b.local_addr().unwrap();
    // Leave the connection pending on the listener side so dropping the
    // selected listener exercises the kernel's reuseport migration path
    // instead of handing an already-accepted socket to userspace.
    let client = connect(addr).await.unwrap();
    assert!(
        read_hits(&path_hits, SELECT_HITS_INDEX) > 0,
        "{label}: initial selection path did not run",
    );

    drop(listener_a);

    // Confirm that the migrate-capable BPF path ran, not just the kernel's
    // default SO_REUSEPORT selection logic choosing a surviving listener.
    assert!(
        read_hits(&path_hits, MIGRATE_HITS_INDEX) > 0,
        "{label}: migration path did not run",
    );
    assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
    let surviving_group_indices = [1u32, MIGRATE_SOCKET_INDEX];
    // Switch to polling on the underlying std listeners here: the
    // migration path can make a connection accept-ready on the surviving
    // listener without a fresh tokio readiness event.
    let listener_b = listener_b.into_std().unwrap();
    let listener_c = listener_c.into_std().unwrap();
    let (accepted_idx, server) = wait_for_accept_polling([&listener_b, &listener_c]).await;
    assert_eq!(
        surviving_group_indices[accepted_idx], MIGRATE_SOCKET_INDEX,
        "{label}: migration should steer the connection to listener C",
    );
    assert_connection_works(client, server).await;
}
