use std::{
    io,
    os::fd::{AsFd as _, AsRawFd as _},
    ptr,
};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{SockMap, sock::SockMapFd},
    programs::{
        Program,
        links::{FdLink, LinkError, LinkType, PinnedLink},
    },
    util::KernelVersion,
};
use aya_obj::generated::bpf_attach_type::{
    self, BPF_SK_MSG_VERDICT, BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT,
};
use rstest::rstest;

#[rstest]
#[case::message("message", BPF_SK_MSG_VERDICT)]
#[case::parser("parser", BPF_SK_SKB_STREAM_PARSER)]
#[case::verdict("verdict", BPF_SK_SKB_STREAM_VERDICT)]
#[test_attr(test_log::test)]
fn link_lifetime(#[case] name: &str, #[case] attach_type: bpf_attach_type) {
    let kernel = KernelVersion::current().unwrap();
    if kernel < KernelVersion::new(5, 18, 0) {
        eprintln!("skipping sockmap link lifetime test: attachment queries require Linux 5.18");
        return;
    }

    let mut bpf = Ebpf::load(crate::SOCK_MAP).unwrap();
    let map = SockMap::try_from(bpf.take_map("SOCKETS_BTF").unwrap()).unwrap();
    let map = map.fd();
    assert_eq!(attached_program(map, attach_type), None);

    macro_rules! attach {
        ($program:ident) => {{
            $program.load().unwrap();
            let program_id = $program.info().unwrap().id();
            let link_id = $program.attach(map).unwrap();
            assert_eq!(attached_program(map, attach_type), Some(program_id));
            let link = $program.take_link(link_id).unwrap();
            (program_id, FdLink::try_from(link))
        }};
    }

    let (program_id, link) = match bpf.program_mut(name).unwrap() {
        Program::SkMsg(program) => attach!(program),
        Program::SkSkb(program) => attach!(program),
        program => panic!("unexpected program: {program:?}"),
    };
    drop(bpf);

    if kernel < KernelVersion::new(6, 10, 0) {
        assert_matches!(link.unwrap_err(), LinkError::InvalidLink);
    } else {
        let link = link.unwrap();
        let info = link.info().unwrap();
        assert_eq!(info.program_id(), program_id);
        assert_eq!(info.link_type().unwrap(), LinkType::SockMap);
        assert_eq!(attached_program(map, attach_type), Some(program_id));

        let directory = tempfile::Builder::new()
            .prefix("sockmap-")
            .tempdir_in("/sys/fs/bpf")
            .unwrap();
        let path = directory.path().join("link");
        let link = link.pin(&path).unwrap();
        drop(link);
        assert_eq!(attached_program(map, attach_type), Some(program_id));

        let link = PinnedLink::from_pin(&path).unwrap();
        let link = link.unpin().unwrap();
        assert_eq!(link.info().unwrap().id(), info.id());
        assert_eq!(attached_program(map, attach_type), Some(program_id));
        drop(link);
    }

    assert_eq!(attached_program(map, attach_type), None);
}

fn attached_program(map: &SockMapFd, attach_type: bpf_attach_type) -> Option<u32> {
    let mut program_id = 0;
    let mut count = 1;
    // SAFETY: Both output pointers refer to writable values, and count describes
    // the single program-ID slot. Sockmaps allow one program per attach type.
    let result = unsafe {
        libbpf_rs::libbpf_sys::bpf_prog_query(
            map.as_fd().as_raw_fd(),
            attach_type as u32,
            0,
            ptr::null_mut(),
            &raw mut program_id,
            &raw mut count,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    match count {
        0 => None,
        1 => Some(program_id),
        count => panic!("unexpected number of attached programs: {count}"),
    }
}
