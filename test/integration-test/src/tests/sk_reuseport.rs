use std::{
    io,
    io::{ErrorKind, Read as _, Write as _},
    net::{
        Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener as StdTcpListener,
        TcpStream as StdTcpStream,
    },
    os::fd::AsRawFd as _,
    time::Duration,
};

use aya::{
    Ebpf,
    maps::{Array, MapData, ReusePortSockArray},
    programs::{ProgramError, SkReuseport, SkReuseportError},
    util::KernelVersion,
};
use integration_common::sk_reuseport::{
    CLEAR_FALLBACK_HITS_INDEX, MIGRATE_HITS_INDEX, MIGRATE_SOCKET_INDEX, SELECT_HITS_INDEX,
    SELECT_SOCKET_INDEX,
};
use libc::{EINVAL, ENOENT};
use nix::sys::socket::{
    AddressFamily, Backlog, Shutdown, SockFlag, SockType, SockaddrIn, bind, listen, setsockopt,
    shutdown, socket, sockopt::ReusePort,
};
use tokio::{
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream},
    time::{sleep, timeout},
};

use crate::utils::NetNsGuard;

const RETRY_DURATION: Duration = Duration::from_millis(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);
const HITS_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct SkReuseportVariant {
    label: &'static str,
    socket_map: &'static str,
    select_prog: &'static str,
    clear_prog: &'static str,
    migrate_prog: &'static str,
}

const SK_REUSEPORT_VARIANTS: &[SkReuseportVariant] = &[
    SkReuseportVariant {
        label: "legacy",
        socket_map: "socket_map",
        select_prog: "select_socket",
        clear_prog: "select_socket_after_clear",
        migrate_prog: "select_or_migrate_socket",
    },
    SkReuseportVariant {
        label: "btf",
        socket_map: "socket_map_btf",
        select_prog: "select_socket_btf",
        clear_prog: "select_socket_after_clear_btf",
        migrate_prog: "select_or_migrate_socket_btf",
    },
];

fn reuseport_listener(port: u16) -> io::Result<StdTcpListener> {
    // `SO_REUSEPORT` must be set before `bind(2)`. The kernel only adds a
    // socket to a reuseport group during bind:
    // - Bind requires both the existing and new sockets to have
    //   `SO_REUSEPORT` set; if either side lacks it, bind fails with
    //   `EADDRINUSE`.
    // - Setting `SO_REUSEPORT` after bind is silently ignored; the socket is
    //   not added to any reuseport group.
    // `std::net::TcpListener` does not expose that pre-bind socket setup step,
    // so the test uses `nix` to create and configure the socket directly.
    let fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(io::Error::other)?;

    setsockopt(&fd, ReusePort, &true).map_err(io::Error::other)?;

    let addr = SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    bind(fd.as_raw_fd(), &addr).map_err(io::Error::other)?;
    listen(&fd, Backlog::MAXCONN).map_err(io::Error::other)?;

    Ok(StdTcpListener::from(fd))
}

fn reuseport_group() -> io::Result<[StdTcpListener; 3]> {
    let first = reuseport_listener(0)?;
    let port = first.local_addr()?.port();
    Ok([first, reuseport_listener(port)?, reuseport_listener(port)?])
}

fn reuseport_pair() -> io::Result<[StdTcpListener; 2]> {
    let first = reuseport_listener(0)?;
    let port = first.local_addr()?.port();
    Ok([first, reuseport_listener(port)?])
}

fn set_nonblocking<const N: usize>(listeners: [&StdTcpListener; N]) {
    for listener in listeners {
        listener.set_nonblocking(true).unwrap();
    }
}

fn tokio_listeners(
    [first, second, third]: [&StdTcpListener; 3],
) -> io::Result<[TokioTcpListener; 3]> {
    first.set_nonblocking(true)?;
    second.set_nonblocking(true)?;
    third.set_nonblocking(true)?;
    Ok([
        TokioTcpListener::from_std(first.try_clone()?)?,
        TokioTcpListener::from_std(second.try_clone()?)?,
        TokioTcpListener::from_std(third.try_clone()?)?,
    ])
}

fn read_hits(hits: &Array<MapData, u64>, index: u32) -> u64 {
    hits.get(&index, 0).unwrap()
}

async fn wait_for_hits(hits: &Array<MapData, u64>, index: u32) -> bool {
    timeout(HITS_TIMEOUT, async {
        loop {
            if read_hits(hits, index) > 0 {
                return;
            }

            sleep(RETRY_DURATION).await;
        }
    })
    .await
    .is_ok()
}

async fn wait_for_accept_tokio(
    listeners: &[TokioTcpListener; 3],
) -> io::Result<(usize, StdTcpStream)> {
    timeout(ACCEPT_TIMEOUT, async {
        let [first, second, third] = listeners;
        let (idx, accepted) = tokio::select! {
            accepted = first.accept() => (0, accepted),
            accepted = second.accept() => (1, accepted),
            accepted = third.accept() => (2, accepted),
        };
        let (stream, _) = accepted?;
        let stream = stream.into_std()?;
        stream.set_nonblocking(false)?;
        Ok((idx, stream))
    })
    .await
    .map_err(|tokio::time::error::Elapsed { .. }| {
        io::Error::new(
            ErrorKind::TimedOut,
            "timed out waiting for accepted connection",
        )
    })?
}

// The migrate test intentionally does not use `TokioTcpListener::accept()`.
// After the kernel migrates a pending connection from one reuseport listener
// to another, the target listener may not receive a fresh readiness event even
// though a subsequent nonblocking `accept()` succeeds. Polling the original
// listener FDs preserves the old test's state-based semantics while still
// yielding via `tokio::sleep()`.
async fn wait_for_accept_polling<const N: usize>(
    listeners: [&StdTcpListener; N],
) -> io::Result<(usize, StdTcpStream)> {
    timeout(ACCEPT_TIMEOUT, async {
        loop {
            for (idx, listener) in listeners.iter().enumerate() {
                match listener.accept() {
                    Ok((stream, _)) => return Ok((idx, stream)),
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
            }

            sleep(RETRY_DURATION).await;
        }
    })
    .await
    .map_err(|tokio::time::error::Elapsed { .. }| {
        io::Error::new(
            ErrorKind::TimedOut,
            "timed out waiting for accepted connection",
        )
    })?
}

async fn connect(addr: SocketAddr) -> io::Result<StdTcpStream> {
    let stream = TokioTcpStream::connect(addr).await?;
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn assert_connection_works(client: &mut StdTcpStream, server: &mut StdTcpStream) {
    client.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    server.set_read_timeout(Some(IO_TIMEOUT)).unwrap();

    client.write_all(b"aya").unwrap();
    let mut buf = [0; 3];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"aya");
}

// `NetNsGuard` switches the current thread into a dedicated network namespace,
// so these async tests must stay on a single runtime thread.
#[tokio::test]
#[test_log::test]
async fn sk_reuseport_selects_expected_listener() {
    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let mut socket_array: ReusePortSockArray<_> = ebpf
            .take_map(variant.socket_map)
            .unwrap()
            .try_into()
            .unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let listeners = reuseport_group().unwrap();
        let acceptors = tokio_listeners([&listeners[0], &listeners[1], &listeners[2]]).unwrap();
        let addr = listeners[SELECT_SOCKET_INDEX as usize]
            .local_addr()
            .unwrap();

        for (index, listener) in listeners.iter().enumerate() {
            socket_array.set(index as u32, listener, 0).unwrap();
        }

        {
            // Limit the mutable borrow of `ebpf` from `program_mut()` to this block.
            let prog: &mut SkReuseport = ebpf
                .program_mut(variant.select_prog)
                .unwrap()
                .try_into()
                .unwrap();
            prog.load().unwrap();
            prog.attach(&listeners[0]).unwrap();
        }

        let mut client = connect(addr).await.unwrap();
        let (accepted_idx, mut server) = wait_for_accept_tokio(&acceptors).await.unwrap();
        assert_eq!(
            accepted_idx,
            SELECT_SOCKET_INDEX as usize,
            "{label}: connection should be steered to listener A",
            label = variant.label,
        );

        // Confirm that the BPF select path ran, not just the kernel's default
        // SO_REUSEPORT selection logic landing on listener A by chance.
        assert!(
            wait_for_hits(&path_hits, SELECT_HITS_INDEX).await,
            "{label}: select path did not run",
            label = variant.label,
        );
        assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
        assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
        assert_connection_works(&mut client, &mut server);

        let prog: &mut SkReuseport = ebpf
            .program_mut(variant.select_prog)
            .unwrap()
            .try_into()
            .unwrap();

        // `SkReuseport` attachments are group-scoped: detaching through any socket in
        // the reuseport group removes the program from the whole group, even if that
        // socket was not used for attach, so a second detach through listener A yields
        // ENOENT.
        prog.detach(&listeners[1]).unwrap();

        let err = prog.detach(&listeners[0]).unwrap_err();
        match err {
            ProgramError::SkReuseportError(SkReuseportError::SetsockoptError {
                option,
                io_error,
            }) => {
                assert_eq!(option, "SO_DETACH_REUSEPORT_BPF");
                assert_eq!(io_error.raw_os_error(), Some(ENOENT));
            }
            err => panic!("unexpected error for {}: {err:?}", variant.label),
        }
    }
}

#[tokio::test]
#[test_log::test]
async fn sk_reuseport_clear_index_changes_selection() {
    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let mut socket_array: ReusePortSockArray<_> = ebpf
            .take_map(variant.socket_map)
            .unwrap()
            .try_into()
            .unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let [listener_a, listener_b, listener_c] = reuseport_group().unwrap();
        let acceptors = tokio_listeners([&listener_a, &listener_b, &listener_c]).unwrap();
        let addr = listener_a.local_addr().unwrap();

        for (index, listener) in [&listener_a, &listener_b, &listener_c]
            .into_iter()
            .enumerate()
        {
            socket_array.set(index as u32, listener, 0).unwrap();
        }

        {
            // Limit the mutable borrow of `ebpf` from `program_mut()` to this block.
            let prog: &mut SkReuseport = ebpf
                .program_mut(variant.clear_prog)
                .unwrap()
                .try_into()
                .unwrap();
            prog.load().unwrap();
            prog.attach(&listener_a).unwrap();
        }

        let mut first_client = connect(addr).await.unwrap();
        let (first_accepted_idx, mut first_server) =
            wait_for_accept_tokio(&acceptors).await.unwrap();
        assert_eq!(
            first_accepted_idx,
            SELECT_SOCKET_INDEX as usize,
            "{label}: before clearing key 0, the program should steer to listener A",
            label = variant.label,
        );
        assert!(
            wait_for_hits(&path_hits, SELECT_HITS_INDEX).await,
            "{label}: select path did not run before clear",
            label = variant.label,
        );
        assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
        assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
        assert_connection_works(&mut first_client, &mut first_server);

        socket_array.clear_index(&SELECT_SOCKET_INDEX).unwrap();

        let mut second_client = connect(addr).await.unwrap();
        let (second_accepted_idx, mut second_server) =
            wait_for_accept_tokio(&acceptors).await.unwrap();
        assert_eq!(
            second_accepted_idx,
            MIGRATE_SOCKET_INDEX as usize,
            "{label}: after clearing key 0, the program should fall back to listener C",
            label = variant.label,
        );
        assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
        // Confirm that the test program observed the missing primary key and
        // explicitly selected listener C, rather than relying on the kernel's
        // default SO_REUSEPORT selection logic.
        assert!(
            wait_for_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX).await,
            "{label}: clear fallback path did not run",
            label = variant.label,
        );
        assert_connection_works(&mut second_client, &mut second_server);
    }
}

#[tokio::test]
#[test_log::test]
async fn sk_reuseport_detaches_after_unload() {
    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let listeners = reuseport_pair().unwrap();

        let prog: &mut SkReuseport = ebpf
            .program_mut(variant.select_prog)
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.attach(&listeners[0]).unwrap();
        prog.unload().unwrap();

        // `SO_DETACH_REUSEPORT_BPF` identifies the group solely from the
        // socket, so detaching should still succeed after the local program FD
        // has been unloaded.
        prog.detach(&listeners[1]).unwrap();

        let err = prog.detach(&listeners[0]).unwrap_err();
        match err {
            ProgramError::SkReuseportError(SkReuseportError::SetsockoptError {
                option,
                io_error,
            }) => {
                assert_eq!(option, "SO_DETACH_REUSEPORT_BPF");
                assert_eq!(io_error.raw_os_error(), Some(ENOENT));
            }
            err => panic!("unexpected error for {}: {err:?}", variant.label),
        }
    }
}

#[tokio::test]
#[test_log::test]
async fn sk_reuseport_migrates_to_expected_listener() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 14, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, sk_reuseport/migrate requires 5.14");
        return;
    }

    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();
        match std::fs::write("/proc/sys/net/ipv4/tcp_migrate_req", "1") {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::PermissionDenied
                        | ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                eprintln!("skipping test - tcp_migrate_req not configurable in test netns: {err}");
                return;
            }
            Err(err) => panic!("unexpected error configuring tcp_migrate_req: {err}"),
        }

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let mut socket_array: ReusePortSockArray<_> = ebpf
            .take_map(variant.socket_map)
            .unwrap()
            .try_into()
            .unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let [listener_a, listener_b, listener_c] = reuseport_group().unwrap();

        for (index, listener) in [&listener_a, &listener_b, &listener_c]
            .into_iter()
            .enumerate()
        {
            socket_array.set(index as u32, listener, 0).unwrap();
        }

        let prog: &mut SkReuseport = ebpf
            .program_mut(variant.migrate_prog)
            .unwrap()
            .try_into()
            .unwrap();
        match prog.load() {
            Ok(()) => {}
            Err(ProgramError::LoadError { io_error, .. })
                if io_error.raw_os_error() == Some(EINVAL) =>
            {
                eprintln!(
                    "skipping {label} test - kernel rejected BPF_SK_REUSEPORT_SELECT_OR_MIGRATE at load",
                    label = variant.label,
                );
                continue;
            }
            Err(err) => panic!(
                "unexpected error loading sk_reuseport/migrate program for {}: {err}",
                variant.label
            ),
        }

        {
            // Limit the mutable borrow of `ebpf` from `program_mut()` to this block.
            let prog: &mut SkReuseport = ebpf
                .program_mut(variant.migrate_prog)
                .unwrap()
                .try_into()
                .unwrap();
            prog.attach(&listener_a).unwrap();
        }

        let addr = listener_b.local_addr().unwrap();
        set_nonblocking([&listener_b, &listener_c]);

        // Leave the connection pending on the listener side so listener shutdown
        // exercises the kernel's reuseport migration path instead of handing an
        // already-accepted socket to userspace.
        let mut client = connect(addr).await.unwrap();
        assert!(
            wait_for_hits(&path_hits, SELECT_HITS_INDEX).await,
            "{label}: initial selection path did not run",
            label = variant.label,
        );

        shutdown(listener_a.as_raw_fd(), Shutdown::Both).unwrap();

        // Confirm that the migrate-capable BPF path ran, not just the kernel's
        // default SO_REUSEPORT selection logic choosing a surviving listener.
        assert!(
            wait_for_hits(&path_hits, MIGRATE_HITS_INDEX).await,
            "{label}: migration path did not run",
            label = variant.label,
        );
        assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
        let surviving_group_indices = [1u32, MIGRATE_SOCKET_INDEX];
        // Use the polling helper here: the migration path can make a connection
        // accept-ready on the surviving listener without a new readiness event.
        let (accepted_idx, mut server) = wait_for_accept_polling([&listener_b, &listener_c])
            .await
            .unwrap();
        assert_eq!(
            surviving_group_indices[accepted_idx],
            MIGRATE_SOCKET_INDEX,
            "{label}: migration should steer the connection to listener C",
            label = variant.label,
        );
        assert_connection_works(&mut client, &mut server);
    }
}
