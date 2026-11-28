use std::{io, net::UdpSocket, time::Duration};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::Array,
    programs::{
        Link as _, ProgramError, SchedClassifier, TcAttach, TcAttachType,
        tc::{
            NlOptions, SchedClassifierLink, TcError, TcHandle, qdisc_add_clsact,
            qdisc_detach_program,
        },
    },
    test_helpers::NetNsGuard,
};
use rstest::rstest;

use crate::TCX;

/// Verify adoption replaces the program on the existing filter and transfers cleanup.
/// Send traffic and inspect each program's independent SEEN map: failed adoption
/// leaves only the old program running; retry switches execution to the new program
/// even after dropping the old owner; detach leaves neither program running.
/// Link accessors separately check retained wrapper metadata, not kernel attributes.
#[test_log::test]
fn netlink_adopt_link_preserves_filter() {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact(c"lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let mut old_seen: Array<_, u32> = bpf.take_map("SEEN").unwrap().try_into().unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let old_program_id = prog.info().unwrap().id();

    let parent: TcHandle = TcAttachType::Ingress.into();
    // Use an explicit nonzero priority to check preservation.
    let priority = 42;
    let handle = TcHandle::new(1, 1);
    let classid = TcHandle::new(1, 2);
    let link_id = prog
        .attach(
            c"lo",
            TcAttach::Netlink {
                parent,
                options: NlOptions {
                    priority,
                    handle,
                    classid: Some(classid),
                },
            },
        )
        .unwrap();
    let link = prog.take_link(link_id).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let round_trip = || {
        const PAYLOAD: &[u8] = b"hello tc";
        assert_eq!(socket.send_to(PAYLOAD, addr).unwrap(), PAYLOAD.len());
        let mut buf = [0; PAYLOAD.len() + 1];
        // In this private netns, send and receive one datagram at a time.
        // Receiving it waits for the ingress hook before inspecting either program's map.
        let len = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], PAYLOAD);
    };
    round_trip();
    assert_eq!(old_seen.get(&0, 0).unwrap(), 1);
    old_seen.set(0, &0, 0).unwrap();

    let mut new_bpf = Ebpf::load(TCX).unwrap();
    let mut new_seen: Array<_, u32> = new_bpf.take_map("SEEN").unwrap().try_into().unwrap();
    let new_prog: &mut SchedClassifier =
        new_bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    new_prog.load().unwrap();
    let new_program_id = new_prog.info().unwrap().id();
    assert_ne!(new_program_id, old_program_id);
    // An invalid replacement name must leave the original filter alive and owned.
    let original_id = link.id();
    // TCA_BPF_NAME allows at most 256 bytes excluding the trailing NUL;
    // 257 ASCII bytes trigger Aya's name-length validation during adoption.
    let mut invalid =
        SchedClassifier::from_program_info(new_prog.info().unwrap(), "a".repeat(257).into())
            .unwrap();
    let (error, link) = invalid.adopt_link(link).unwrap_err();
    assert_matches!(error, ProgramError::TcError(TcError::NetlinkError(_)));
    assert_eq!(link.id(), original_id);
    round_trip();
    assert_eq!(old_seen.get(&0, 0).unwrap(), 1);
    assert_eq!(new_seen.get(&0, 0).unwrap(), 0);
    old_seen.set(0, &0, 0).unwrap();

    let new_link_id = new_prog.adopt_link(link).unwrap();
    drop(bpf);
    round_trip();
    assert_eq!(old_seen.get(&0, 0).unwrap(), 0);
    assert_eq!(new_seen.get(&0, 0).unwrap(), 1);

    let new_link = new_prog.take_link(new_link_id).unwrap();
    // Check that the returned link retains the original attachment parameters.
    // The traffic assertions above verify that the new program runs.
    assert_eq!(new_link.classid().unwrap(), Some(classid));
    assert_eq!(new_link.parent().unwrap(), parent);
    assert_eq!(new_link.priority().unwrap(), priority);
    assert_eq!(new_link.handle().unwrap(), handle);
    new_link.detach().unwrap();
    assert_matches!(
        qdisc_detach_program(c"lo", parent, "tcx_next"),
        Err(TcError::IoError(error)) if error.kind() == io::ErrorKind::NotFound
    );
    new_seen.set(0, &0, 0).unwrap();
    round_trip();
    assert_eq!(old_seen.get(&0, 0).unwrap(), 0);
    assert_eq!(new_seen.get(&0, 0).unwrap(), 0);
}

/// Verify that [`TcHandle::AUTO_ASSIGN`] triggers kernel allocation: the
/// handle reported after attach must differ from the sentinel.
#[test_log::test]
fn netlink_attach_auto_assigns_handle() {
    let _netns = NetNsGuard::new().unwrap();

    qdisc_add_clsact(c"lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let link_id = prog
        .attach(
            c"lo",
            TcAttach::Netlink {
                parent: TcAttachType::Ingress.into(),
                options: NlOptions::default(),
            },
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_ne!(link.handle().unwrap(), TcHandle::AUTO_ASSIGN);
    let reconstructed = SchedClassifierLink::from_netlink_parts(
        c"lo",
        link.parent().unwrap(),
        link.priority().unwrap(),
        link.handle().unwrap(),
        link.classid().unwrap(),
    )
    .unwrap();
    // The original netlink wrapper owns no fd. Only the reconstructed wrapper
    // should detach the filter shared by these two wrappers.
    let _original_link = std::mem::ManuallyDrop::new(link);
    reconstructed.detach().unwrap();
    assert_matches!(
        qdisc_detach_program(c"lo", TcAttachType::Ingress.into(), "tcx_next"),
        Err(TcError::IoError(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        }
    );
}

/// Verify that an explicit [`TcHandle`] is preserved across netlink attach.
#[test_log::test]
fn netlink_attach_preserves_explicit_handle() {
    let _netns = NetNsGuard::new().unwrap();

    qdisc_add_clsact(c"lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let handle = TcHandle::new(1, 0xfffe);

    let link_id = prog
        .attach(
            c"lo",
            TcAttach::Netlink {
                parent: TcAttachType::Ingress.into(),
                options: NlOptions {
                    handle,
                    ..Default::default()
                },
            },
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_eq!(link.handle().unwrap(), handle);
}

// The kernel's NLA_NUL_STRING limit excludes the trailing NUL. Adjacent lengths
// also exercise the padding between TCA_BPF_NAME and TCA_BPF_FLAGS.
#[rstest]
#[case::unaligned(254, true)]
#[case::aligned(255, true)]
#[case::maximum(256, true)]
#[case::too_long(257, false)]
#[test_log::test]
fn netlink_program_name(#[case] len: usize, #[case] valid: bool) {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact(c"lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let name = "a".repeat(len);
    let mut prog =
        SchedClassifier::from_program_info(prog.info().unwrap(), name.clone().into()).unwrap();
    let result = prog.attach(
        c"lo",
        TcAttach::Netlink {
            parent: TcAttachType::Ingress.into(),
            options: NlOptions {
                classid: Some(TcHandle::new(1, 1)),
                ..Default::default()
            },
        },
    );
    if valid {
        let _link = prog.take_link(result.unwrap()).unwrap();
        // Looking up the full name verifies that the kernel received it intact.
        qdisc_detach_program(c"lo", TcHandle::new(0xffff, 0xfff2), &name).unwrap();
    } else {
        assert_matches!(result, Err(ProgramError::TcError(TcError::NetlinkError(err))) => {
            assert_eq!(err.to_string(), "program name exceeds CLS_BPF_NAME_LEN");
        });
    }
}
