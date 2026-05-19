use std::{
    io::ErrorKind,
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::fd::AsRawFd as _,
    time::Duration,
};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapType, SockHash, SockMap},
    programs::{ProgramType, SkLookup},
    sys::{is_map_supported, is_program_supported},
};
use libc::ENOENT;
use test_case::test_case;

use crate::utils::NetNsGuard;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MISS_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug)]
enum MapKind {
    Hash,
    Map,
}

impl MapKind {
    const fn map_type(self) -> MapType {
        match self {
            Self::Hash => MapType::SockHash,
            Self::Map => MapType::SockMap,
        }
    }

    fn insert_canary(self, bpf: &mut Ebpf, name: &str, canary: &TcpListener) {
        match self {
            Self::Hash => {
                let mut m: SockHash<_, u32> = bpf
                    .map_mut(name)
                    .unwrap_or_else(|| panic!("missing map {name}"))
                    .try_into()
                    .unwrap_or_else(|err| panic!("map {name} is not a SockHash: {err}"));
                m.insert(0u32, canary.as_raw_fd(), 0)
                    .expect("insert canary");
            }
            Self::Map => {
                let mut m: SockMap<_> = bpf
                    .map_mut(name)
                    .unwrap_or_else(|| panic!("missing map {name}"))
                    .try_into()
                    .unwrap_or_else(|err| panic!("map {name} is not a SockMap: {err}"));
                m.set(0, canary, 0).expect("insert canary");
            }
        }
    }
}

#[test_log::test(test_case(crate::SOCK_HASH, MapKind::Hash, "SOCKETS_LEGACY", "sk_lookup_legacy" ; "sock_hash legacy"))]
#[test_case(crate::SOCK_HASH, MapKind::Hash, "SOCKETS_BTF", "sk_lookup_btf" ; "sock_hash btf")]
#[test_case(crate::SOCK_MAP, MapKind::Map, "SOCKETS_LEGACY", "sk_lookup_legacy" ; "sock_map legacy")]
#[test_case(crate::SOCK_MAP, MapKind::Map, "SOCKETS_BTF", "sk_lookup_btf" ; "sock_map btf")]
fn redirect_sk_lookup(bpf_bytes: &[u8], kind: MapKind, map_name: &str, prog_name: &str) {
    if !is_map_supported(kind.map_type()).unwrap() {
        eprintln!("skipping test - {:?} not supported", kind.map_type());
        return;
    }
    if !is_program_supported(ProgramType::SkLookup).unwrap() {
        eprintln!("skipping test - sk_lookup not supported");
        return;
    }

    let netns = NetNsGuard::new();

    let canary = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind canary listener");

    // Reserve and immediately release a port so the kernel's normal lookup
    // misses; SK_LOOKUP must then redirect the SYN to canary.
    let probe_addr = {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe listener");
        probe.local_addr().expect("probe local_addr")
    };

    let mut bpf = EbpfLoader::new().load(bpf_bytes).expect("load bpf program");

    kind.insert_canary(&mut bpf, map_name, &canary);

    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    prog.load()
        .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
    prog.attach(&netns)
        .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

    let stream =
        TcpStream::connect_timeout(&probe_addr, CONNECT_TIMEOUT).expect("connect to probe address");

    canary.accept().expect("canary accept failed");

    drop(stream);
}

#[test_log::test(test_case(crate::SOCK_HASH, MapKind::Hash, "sk_lookup_legacy" ; "sock_hash legacy"))]
#[test_case(crate::SOCK_HASH, MapKind::Hash, "sk_lookup_btf" ; "sock_hash btf")]
#[test_case(crate::SOCK_MAP, MapKind::Map, "sk_lookup_legacy" ; "sock_map legacy")]
#[test_case(crate::SOCK_MAP, MapKind::Map, "sk_lookup_btf" ; "sock_map btf")]
fn redirect_sk_lookup_miss_propagates_enoent(bpf_bytes: &[u8], kind: MapKind, prog_name: &str) {
    if !is_map_supported(kind.map_type()).unwrap() {
        eprintln!("skipping test - {:?} not supported", kind.map_type());
        return;
    }
    if !is_program_supported(ProgramType::SkLookup).unwrap() {
        eprintln!("skipping test - sk_lookup not supported");
        return;
    }

    let netns = NetNsGuard::new();

    // Empty map: `redirect_sk_lookup` must return `Err(-ENOENT)` and the BPF
    // program records it in LAST_ERRNO before returning SK_DROP.
    let probe_addr = {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe listener");
        probe.local_addr().expect("probe local_addr")
    };

    let mut bpf = EbpfLoader::new().load(bpf_bytes).expect("load bpf program");

    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    prog.load()
        .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
    prog.attach(&netns)
        .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

    let err = TcpStream::connect_timeout(&probe_addr, MISS_TIMEOUT)
        .expect_err("connect should fail when redirect_sk_lookup misses");
    assert_eq!(err.kind(), ErrorKind::ConnectionRefused, "got {err:?}");

    let last_errno: Array<_, i32> = bpf
        .take_map("LAST_ERRNO")
        .expect("missing LAST_ERRNO map")
        .try_into()
        .expect("LAST_ERRNO is not an Array");
    assert_eq!(last_errno.get(&0, 0).unwrap(), -ENOENT);
}
