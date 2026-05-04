use std::{
    fs::File,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    time::{Duration, Instant},
};

use aya::{
    EbpfLoader,
    maps::{MapType, SockMap},
    programs::{ProgramType, SkLookup},
    sys::{is_map_supported, is_program_supported},
};
use test_case::test_case;

use crate::utils::NetNsGuard;

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[test_case("SOCKETS_LEGACY", "sk_lookup_legacy" ; "legacy")]
#[test_case("SOCKETS_BTF", "sk_lookup_btf" ; "btf")]
#[test_log::test]
fn sock_map_redirect_sk_lookup(map_name: &str, prog_name: &str) {
    if !is_map_supported(MapType::SockMap).unwrap() {
        eprintln!("skipping test - sockmap not supported");
        return;
    }
    if !is_program_supported(ProgramType::SkLookup).unwrap() {
        eprintln!("skipping test - sk_lookup not supported");
        return;
    }

    let _netns = NetNsGuard::new();

    let canary = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind canary listener");
    canary
        .set_nonblocking(true)
        .expect("canary set_nonblocking");

    // Reserve and immediately release a port so the kernel's normal lookup
    // misses; SK_LOOKUP must then redirect the SYN to canary.
    let probe_addr = {
        let probe = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind probe listener");
        probe.local_addr().expect("probe local_addr")
    };

    let mut bpf = EbpfLoader::new()
        .load(crate::SOCK_MAP)
        .expect("load sock_map program");

    let mut sock_map: SockMap<_> = bpf
        .take_map(map_name)
        .unwrap_or_else(|| panic!("missing map {map_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("map {map_name} is not a SockMap: {err}"));
    sock_map
        .set(0, &canary, 0)
        .expect("insert canary into sock_map");

    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    prog.load()
        .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
    let netns = File::open("/proc/thread-self/ns/net").expect("open netns");
    prog.attach(netns)
        .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

    let _client =
        TcpStream::connect_timeout(&probe_addr, ACCEPT_TIMEOUT).expect("connect to probe address");

    let start = Instant::now();
    loop {
        match canary.accept() {
            Ok((_, _)) => return,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => panic!("canary accept failed: {err}"),
        }
        assert!(
            start.elapsed() < ACCEPT_TIMEOUT,
            "no listener accepted within {ACCEPT_TIMEOUT:?}",
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}
