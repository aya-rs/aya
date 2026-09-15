use std::{
    io::ErrorKind,
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::fd::AsRawFd as _,
    time::Duration,
};

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapType, SockHash, SockMap},
    programs::{ProgramError, ProgramType, SkLookup},
    sys::is_program_supported,
    test_helpers::NetNsGuard,
};
use libc::{EINVAL, ENOENT};
use rstest::rstest;

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
                m.insert(&0u32, canary.as_raw_fd(), 0)
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

fn load_sk_lookup(prog: &mut SkLookup) -> bool {
    if is_program_supported(ProgramType::SkLookup).unwrap() {
        prog.load().expect("load sk_lookup program");
        true
    } else {
        assert_matches!(prog.load(), Err(ProgramError::LoadError { io_error, verifier_log }) => {
            assert_eq!(io_error.raw_os_error(), Some(EINVAL));
            assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
        });
        false
    }
}

fn load_maps_or_expect_unsupported(bpf_bytes: &[u8], kind: MapKind) -> Option<Ebpf> {
    let missing = super::unsupported_map_names([
        (kind.map_type(), &["SOCKETS_LEGACY", "SOCKETS_BTF"][..]),
        (MapType::Array, &["LAST_ERRNO"][..]),
    ]);
    super::map_load_or_expect_unsupported(EbpfLoader::new().load(bpf_bytes), &missing)
}

#[rstest]
#[case::sock_hash_legacy(crate::SOCK_HASH, MapKind::Hash, "SOCKETS_LEGACY", "sk_lookup_legacy")]
#[case::sock_hash_btf(crate::SOCK_HASH, MapKind::Hash, "SOCKETS_BTF", "sk_lookup_btf")]
#[case::sock_map_legacy(crate::SOCK_MAP, MapKind::Map, "SOCKETS_LEGACY", "sk_lookup_legacy")]
#[case::sock_map_btf(crate::SOCK_MAP, MapKind::Map, "SOCKETS_BTF", "sk_lookup_btf")]
#[test_attr(test_log::test)]
fn redirect_sk_lookup(
    #[case] bpf_bytes: &[u8],
    #[case] kind: MapKind,
    #[case] map_name: &str,
    #[case] prog_name: &str,
) {
    let Some(mut bpf) = load_maps_or_expect_unsupported(bpf_bytes, kind) else {
        return;
    };
    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    if !load_sk_lookup(prog) {
        return;
    }

    let netns = NetNsGuard::new().unwrap();

    let canary = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind canary listener");

    // Reserve and immediately release a port so the kernel's normal lookup
    // misses; SK_LOOKUP must then redirect the SYN to canary.
    let probe_addr = {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe listener");
        probe.local_addr().expect("probe local_addr")
    };

    kind.insert_canary(&mut bpf, map_name, &canary);

    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    prog.attach(&netns)
        .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

    let stream =
        TcpStream::connect_timeout(&probe_addr, CONNECT_TIMEOUT).expect("connect to probe address");

    canary.accept().expect("canary accept failed");

    drop(stream);
}

#[rstest]
#[case::sock_hash_legacy(crate::SOCK_HASH, MapKind::Hash, "sk_lookup_legacy")]
#[case::sock_hash_btf(crate::SOCK_HASH, MapKind::Hash, "sk_lookup_btf")]
#[case::sock_map_legacy(crate::SOCK_MAP, MapKind::Map, "sk_lookup_legacy")]
#[case::sock_map_btf(crate::SOCK_MAP, MapKind::Map, "sk_lookup_btf")]
#[test_attr(test_log::test)]
fn redirect_sk_lookup_miss_propagates_enoent(
    #[case] bpf_bytes: &[u8],
    #[case] kind: MapKind,
    #[case] prog_name: &str,
) {
    let Some(mut bpf) = load_maps_or_expect_unsupported(bpf_bytes, kind) else {
        return;
    };
    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
    if !load_sk_lookup(prog) {
        return;
    }

    let netns = NetNsGuard::new().unwrap();

    // Empty map: `redirect_sk_lookup` must return `Err(-ENOENT)` and the BPF
    // program records it in LAST_ERRNO before returning SK_DROP.
    let probe_addr = {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe listener");
        probe.local_addr().expect("probe local_addr")
    };

    let prog: &mut SkLookup = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not an SkLookup: {err}"));
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
