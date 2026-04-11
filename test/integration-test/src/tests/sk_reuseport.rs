use std::{
    io,
    io::{ErrorKind, Read as _, Write as _},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    os::fd::AsRawFd as _,
    thread,
    time::{Duration, Instant},
};

use aya::{
    Ebpf,
    maps::{Array, MapData, ReusePortSockArray},
    programs::{ProgramError, SkReuseport, SkReuseportError},
    util::KernelVersion,
};
use libc::{EINVAL, ENOENT};
use nix::sys::socket::{
    AddressFamily, Backlog, Shutdown, SockFlag, SockType, SockaddrIn, bind, listen, setsockopt,
    shutdown, socket, sockopt::ReusePort,
};

use crate::utils::NetNsGuard;

const RETRY_DURATION: Duration = Duration::from_millis(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);
const HITS_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(1);
// Keep these indices aligned with the eBPF-side counters in
// `test/integration-ebpf/src/sk_reuseport.rs`; the userspace tests and the
// eBPF test program are compiled separately, so the constants are duplicated on
// purpose.
const SELECT_HITS_INDEX: u32 = 0;
const MIGRATE_HITS_INDEX: u32 = 1;
const CLEAR_FALLBACK_HITS_INDEX: u32 = 2;
const SELECT_SOCKET_INDEX: u32 = 0;
const MIGRATE_SOCKET_INDEX: u32 = 2;

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

fn reuseport_listener(port: u16) -> io::Result<TcpListener> {
    // `SO_REUSEPORT` must be enabled after `socket(2)` and before `bind(2)`.
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

    Ok(TcpListener::from(fd))
}

fn reuseport_group(size: usize) -> io::Result<Vec<TcpListener>> {
    let first = reuseport_listener(0)?;
    let port = first.local_addr()?.port();
    let mut listeners = vec![first];
    for _ in 1..size {
        listeners.push(reuseport_listener(port)?);
    }
    Ok(listeners)
}

fn set_nonblocking(listeners: &[&TcpListener]) {
    for listener in listeners {
        listener.set_nonblocking(true).unwrap();
    }
}

fn configure_tcp_migrate_req() -> io::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/tcp_migrate_req", "1")
}

fn read_hits(hits: &Array<MapData, u64>, index: u32) -> u64 {
    hits.get(&index, 0).unwrap()
}

fn wait_for_hits(hits: &Array<MapData, u64>, index: u32) -> bool {
    let deadline = Instant::now() + HITS_TIMEOUT;
    loop {
        if read_hits(hits, index) > 0 {
            return true;
        }

        if Instant::now() >= deadline {
            return false;
        }

        thread::sleep(RETRY_DURATION);
    }
}

fn wait_for_accept(listeners: &[&TcpListener]) -> io::Result<(usize, TcpStream)> {
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        for (idx, listener) in listeners.iter().enumerate() {
            match listener.accept() {
                Ok((stream, _)) => return Ok((idx, stream)),
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
        }

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "timed out waiting for accepted connection",
            ));
        }

        thread::sleep(RETRY_DURATION);
    }
}

fn assert_connection_works(client: &mut TcpStream, server: &mut TcpStream) {
    client.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    server.set_read_timeout(Some(IO_TIMEOUT)).unwrap();

    client.write_all(b"aya").unwrap();
    let mut buf = [0; 3];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"aya");
}

#[test_log::test]
fn sk_reuseport_selects_expected_listener() {
    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let mut socket_array: ReusePortSockArray<_> = ebpf
            .take_map(variant.socket_map)
            .unwrap()
            .try_into()
            .unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let listeners = reuseport_group(3).unwrap();
        let addr = listeners[SELECT_SOCKET_INDEX as usize]
            .local_addr()
            .unwrap();

        for (index, listener) in listeners.iter().enumerate() {
            socket_array.set(index as u32, listener, 0).unwrap();
        }
        set_nonblocking(&[&listeners[0], &listeners[1], &listeners[2]]);

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

        let mut client = TcpStream::connect(addr).unwrap();
        let (accepted_idx, mut server) =
            wait_for_accept(&[&listeners[0], &listeners[1], &listeners[2]]).unwrap();
        assert_eq!(
            accepted_idx,
            SELECT_SOCKET_INDEX as usize,
            "{label}: connection should be steered to listener A",
            label = variant.label,
        );

        // Confirm that the BPF select path ran, not just the kernel's default
        // SO_REUSEPORT selection logic landing on listener A by chance.
        assert!(
            wait_for_hits(&path_hits, SELECT_HITS_INDEX),
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
            ProgramError::SkReuseportError(SkReuseportError::SoDetachReuseportBpfError {
                io_error,
            }) => {
                assert_eq!(io_error.raw_os_error(), Some(ENOENT));
            }
            err => panic!("unexpected error for {}: {err:?}", variant.label),
        }
    }
}

#[test_log::test]
fn sk_reuseport_clear_index_changes_selection() {
    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let mut socket_array: ReusePortSockArray<_> = ebpf
            .take_map(variant.socket_map)
            .unwrap()
            .try_into()
            .unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let [listener_a, listener_b, listener_c] = reuseport_group(3)
            .unwrap()
            .try_into()
            .unwrap_or_else(|_: Vec<_>| panic!("expected exactly 3 listeners"));
        let addr = listener_a.local_addr().unwrap();

        for (index, listener) in [&listener_a, &listener_b, &listener_c]
            .into_iter()
            .enumerate()
        {
            socket_array.set(index as u32, listener, 0).unwrap();
        }
        set_nonblocking(&[&listener_a, &listener_b, &listener_c]);

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

        let mut first_client = TcpStream::connect(addr).unwrap();
        let (first_accepted_idx, mut first_server) =
            wait_for_accept(&[&listener_a, &listener_b, &listener_c]).unwrap();
        assert_eq!(
            first_accepted_idx,
            SELECT_SOCKET_INDEX as usize,
            "{label}: before clearing key 0, the program should steer to listener A",
            label = variant.label,
        );
        assert!(
            wait_for_hits(&path_hits, SELECT_HITS_INDEX),
            "{label}: select path did not run before clear",
            label = variant.label,
        );
        assert_eq!(read_hits(&path_hits, MIGRATE_HITS_INDEX), 0);
        assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
        assert_connection_works(&mut first_client, &mut first_server);

        socket_array.clear_index(&SELECT_SOCKET_INDEX).unwrap();

        let mut second_client = TcpStream::connect(addr).unwrap();
        let (second_accepted_idx, mut second_server) =
            wait_for_accept(&[&listener_a, &listener_b, &listener_c]).unwrap();
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
            wait_for_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX),
            "{label}: clear fallback path did not run",
            label = variant.label,
        );
        assert_connection_works(&mut second_client, &mut second_server);
    }
}

#[test_log::test]
fn sk_reuseport_migrates_to_expected_listener() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 14, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, sk_reuseport/migrate requires 5.14");
        return;
    }

    match configure_tcp_migrate_req() {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            eprintln!("skipping test - tcp_migrate_req not configurable: {err}");
            return;
        }
        Err(err) => panic!("unexpected error configuring tcp_migrate_req: {err}"),
    }

    for &variant in SK_REUSEPORT_VARIANTS {
        let _netns = NetNsGuard::new();

        let mut ebpf = Ebpf::load(crate::SK_REUSEPORT).unwrap();
        let mut socket_array: ReusePortSockArray<_> = ebpf
            .take_map(variant.socket_map)
            .unwrap()
            .try_into()
            .unwrap();
        let path_hits: Array<_, u64> = ebpf.take_map("path_hits").unwrap().try_into().unwrap();
        let [listener_a, listener_b, listener_c] = reuseport_group(3)
            .unwrap()
            .try_into()
            .unwrap_or_else(|_: Vec<_>| panic!("expected exactly 3 listeners"));

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
        set_nonblocking(&[&listener_b, &listener_c]);

        // Leave the connection pending on the listener side so listener shutdown
        // exercises the kernel's reuseport migration path instead of handing an
        // already-accepted socket to userspace.
        let mut client = TcpStream::connect(addr).unwrap();
        assert!(
            wait_for_hits(&path_hits, SELECT_HITS_INDEX),
            "{label}: initial selection path did not run",
            label = variant.label,
        );

        shutdown(listener_a.as_raw_fd(), Shutdown::Both).unwrap();

        // Confirm that the migrate-capable BPF path ran, not just the kernel's
        // default SO_REUSEPORT selection logic choosing a surviving listener.
        assert!(
            wait_for_hits(&path_hits, MIGRATE_HITS_INDEX),
            "{label}: migration path did not run",
            label = variant.label,
        );
        assert_eq!(read_hits(&path_hits, CLEAR_FALLBACK_HITS_INDEX), 0);
        let surviving_listeners = [&listener_b, &listener_c];
        let surviving_group_indices = [1u32, MIGRATE_SOCKET_INDEX];
        let (accepted_idx, mut server) = wait_for_accept(&surviving_listeners).unwrap();
        assert_eq!(
            surviving_group_indices[accepted_idx],
            MIGRATE_SOCKET_INDEX,
            "{label}: migration should steer the connection to listener C",
            label = variant.label,
        );
        assert_connection_works(&mut client, &mut server);
    }
}
