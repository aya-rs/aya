use std::{
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd as _,
    time::Duration,
};

use aya::{
    EbpfLoader,
    maps::{MapType, SockHash},
    programs::{ProgramType, SkLookup},
    sys::{is_map_supported, is_program_supported},
};
use test_case::test_case;
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::utils::NetNsGuard;

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);

#[test_case("SOCKETS_LEGACY", "sk_lookup_legacy" ; "legacy")]
#[test_case("SOCKETS_BTF", "sk_lookup_btf" ; "btf")]
#[test_log::test(tokio::test)]
async fn sock_hash_redirect_sk_lookup(map_name: &str, prog_name: &str) {
    if !is_map_supported(MapType::SockHash).unwrap() {
        eprintln!("skipping test - sockhash not supported");
        return;
    }
    if !is_program_supported(ProgramType::SkLookup).unwrap() {
        eprintln!("skipping test - sk_lookup not supported");
        return;
    }

    let netns = NetNsGuard::new();

    let canary = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind canary listener");

    // Reserve and immediately release a port so the kernel's normal lookup
    // misses; SK_LOOKUP must then redirect the SYN to canary.
    let probe_addr = {
        let probe = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind probe listener");
        probe.local_addr().expect("probe local_addr")
    };

    let mut bpf = EbpfLoader::new()
        .load(crate::SOCK_HASH)
        .expect("load sock_hash program");

    let mut sock_hash: SockHash<_, u32> = bpf
        .take_map(map_name)
        .unwrap_or_else(|| panic!("missing map {map_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("map {map_name} is not a SockHash: {err}"));
    sock_hash
        .insert(0u32, canary.as_raw_fd(), 0)
        .expect("insert canary into sock_hash");

    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    prog.load()
        .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
    prog.attach(&netns)
        .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

    let _client = timeout(ACCEPT_TIMEOUT, TcpStream::connect(probe_addr))
        .await
        .expect("connect to probe address timed out")
        .expect("connect to probe address");

    timeout(ACCEPT_TIMEOUT, canary.accept())
        .await
        .expect("canary accept timed out")
        .expect("canary accept failed");
}
