use std::{io, net::UdpSocket, os::fd::AsFd as _, time::Duration};

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
use libbpf_rs::{TC_INGRESS, TcHook, libbpf_sys};
use rstest::rstest;

use crate::TCX;

#[test_log::test]
fn netlink_from_parts_detaches_filter() {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let program_id = prog.info().unwrap().id();
    let parent: TcHandle = TcAttachType::Ingress.into();
    let id = prog
        .attach(
            "lo",
            TcAttach::Netlink {
                parent,
                options: NlOptions::default(),
            },
        )
        .unwrap();
    let link = prog.take_link(id).unwrap();
    let priority = link.priority().unwrap();
    let handle = link.handle().unwrap();
    let if_index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(if_index, 0);
    let mut query = TcHook::new(prog.fd().unwrap().as_fd());
    query
        .ifindex(if_index as i32)
        .attach_point(TC_INGRESS)
        .priority(priority.into())
        .handle(handle.into());
    assert_eq!(query.query().unwrap(), program_id);

    let reconstructed = SchedClassifierLink::from_netlink_parts(
        "lo",
        link.parent().unwrap(),
        priority,
        handle,
        link.classid().unwrap(),
    )
    .unwrap();
    // Both wrappers identify the same kernel filter. Suppress the original
    // wrapper's Drop (which would detach it) so this test verifies cleanup
    // through the reconstructed link. The original netlink wrapper owns no fd.
    let _original_link = std::mem::ManuallyDrop::new(link);
    assert_eq!(query.query().unwrap(), program_id);
    reconstructed.detach().unwrap();
    assert_matches!(
        qdisc_detach_program("lo", parent, "tcx_next"),
        Err(TcError::IoError(error)) if error.kind() == io::ErrorKind::NotFound
    );
}

/// Verify that `classid` set on the initial netlink attach is preserved when
/// the program is later replaced via [`SchedClassifier::adopt_link`].
///
/// `cls_bpf_change` allocates a fresh `cls_bpf_prog` on every netlink replace
/// and only sets `prog->res.classid` if the request carries `TCA_BPF_CLASSID`;
/// without preservation in [`NlOptions::classid`] the binding would be
/// silently cleared on program replacement.
#[test_log::test]
fn netlink_adopt_link_preserves_classid() {
    let _netns = NetNsGuard::new().unwrap();

    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let classid = TcHandle::new(1, 1);

    let link_id = prog
        .attach(
            "lo",
            TcAttach::Netlink {
                parent: TcAttachType::Ingress.into(),
                options: NlOptions {
                    classid: Some(classid),
                    ..Default::default()
                },
            },
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_eq!(link.parent().unwrap(), TcHandle::new(0xffff, 0xfff2));
    assert_eq!(link.classid().unwrap(), Some(classid));

    let new_link_id = prog.adopt_link(link).unwrap();
    let new_link = prog.take_link(new_link_id).unwrap();
    assert_eq!(new_link.parent().unwrap(), TcHandle::new(0xffff, 0xfff2));
    assert_eq!(new_link.classid().unwrap(), Some(classid));
}

/// Verify adoption replaces the program on the existing filter and transfers cleanup.
#[test_log::test]
fn netlink_adopt_link_preserves_filter() {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let mut old_seen: Array<_, u32> = bpf.take_map("SEEN").unwrap().try_into().unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let old_program_id = prog.info().unwrap().id();

    let parent: TcHandle = TcAttachType::Ingress.into();
    let priority = 42;
    let handle = TcHandle::new(1, 1);
    let link_id = prog
        .attach(
            "lo",
            TcAttach::Netlink {
                parent,
                options: NlOptions {
                    priority,
                    handle,
                    ..Default::default()
                },
            },
        )
        .unwrap();
    let link = prog.take_link(link_id).unwrap();

    // Query the original filter to verify that adoption updates it in place.
    let if_index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(if_index, 0);
    let mut query = TcHook::new(prog.fd().unwrap().as_fd());
    query
        .ifindex(if_index as i32)
        .attach_point(TC_INGRESS)
        .priority(priority.into())
        .handle(handle.into());
    assert_eq!(query.query().unwrap(), old_program_id);

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let round_trip = || {
        const PAYLOAD: &[u8] = b"hello tc";
        assert_eq!(socket.send_to(PAYLOAD, addr).unwrap(), PAYLOAD.len());
        let mut buf = [0; PAYLOAD.len() + 1];
        // Wait for the ingress hook to finish before inspecting either program's map.
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
    let new_link_id = new_prog.adopt_link(link).unwrap();
    drop(bpf);
    assert_eq!(query.query().unwrap(), new_program_id);
    round_trip();
    assert_eq!(old_seen.get(&0, 0).unwrap(), 0);
    assert_eq!(new_seen.get(&0, 0).unwrap(), 1);

    let new_link = new_prog.take_link(new_link_id).unwrap();
    assert_eq!(new_link.parent().unwrap(), parent);
    assert_eq!(new_link.priority().unwrap(), priority);
    assert_eq!(new_link.handle().unwrap(), handle);
    new_link.detach().unwrap();
    assert_matches!(
        qdisc_detach_program("lo", parent, "tcx_next"),
        Err(TcError::IoError(error)) if error.kind() == io::ErrorKind::NotFound
    );
    new_seen.set(0, &0, 0).unwrap();
    round_trip();
    assert_eq!(old_seen.get(&0, 0).unwrap(), 0);
    assert_eq!(new_seen.get(&0, 0).unwrap(), 0);
}

#[test_log::test]
fn netlink_adopt_link_failure_returns_link() {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact("lo").unwrap();
    let mut old_bpf = Ebpf::load(TCX).unwrap();
    let old: &mut SchedClassifier = old_bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    old.load().unwrap();
    let old_program_id = old.info().unwrap().id();
    let id = old
        .attach(
            "lo",
            TcAttach::Netlink {
                parent: TcAttachType::Ingress.into(),
                options: NlOptions::default(),
            },
        )
        .unwrap();
    let link = old.take_link(id).unwrap();
    let id = link.id();
    let priority = link.priority().unwrap();
    let handle = link.handle().unwrap();
    let if_index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(if_index, 0);
    let hook = libbpf_sys::bpf_tc_hook {
        sz: size_of::<libbpf_sys::bpf_tc_hook>() as libbpf_sys::size_t,
        ifindex: if_index as i32,
        attach_point: libbpf_sys::BPF_TC_INGRESS,
        ..Default::default()
    };
    let attached_program = || {
        let mut options = libbpf_sys::bpf_tc_opts {
            sz: size_of::<libbpf_sys::bpf_tc_opts>() as libbpf_sys::size_t,
            priority: priority.into(),
            handle: handle.into(),
            ..Default::default()
        };
        // SAFETY: Both structures have their size fields initialized, and options is writable.
        let result = unsafe { libbpf_sys::bpf_tc_query(&raw const hook, &raw mut options) };
        assert_eq!(result, 0);
        options.prog_id
    };

    let mut new_bpf = Ebpf::load(TCX).unwrap();
    let new: &mut SchedClassifier = new_bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    new.load().unwrap();
    let new_program_id = new.info().unwrap().id();
    // TCA_BPF_NAME allows at most 256 bytes excluding the trailing NUL.
    // Use 257 ASCII bytes to trigger Aya's length validation on attach and replace.
    // A failed replacement must also return ownership of the original attachment.
    let name = "a".repeat(257);
    let mut invalid = SchedClassifier::from_program_info(new.info().unwrap(), name.into()).unwrap();
    let attach_error = invalid
        .attach(
            "lo",
            TcAttach::Netlink {
                parent: TcAttachType::Ingress.into(),
                options: NlOptions::default(),
            },
        )
        .unwrap_err();
    let (error, link) = invalid.adopt_link(link).unwrap_err();
    for error in [attach_error, error] {
        assert_matches!(error, ProgramError::TcError(TcError::NetlinkError(error)) => {
            assert_eq!(error.to_string(), "program name exceeds CLS_BPF_NAME_LEN");
        });
    }
    assert_eq!(link.id(), id);
    assert_eq!(attached_program(), old_program_id);

    let id = new.adopt_link(link).unwrap();
    drop(old_bpf);
    assert_eq!(attached_program(), new_program_id);
    new.detach(id).unwrap();
}

/// Verify that [`TcHandle::AUTO_ASSIGN`] triggers kernel allocation: the
/// handle reported after attach must differ from the sentinel.
#[test_log::test]
fn netlink_attach_auto_assigns_handle() {
    let _netns = NetNsGuard::new().unwrap();

    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let link_id = prog
        .attach(
            "lo",
            TcAttach::Netlink {
                parent: TcAttachType::Ingress.into(),
                options: NlOptions::default(),
            },
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_ne!(link.handle().unwrap(), TcHandle::AUTO_ASSIGN);
}

/// Verify that an explicit [`TcHandle`] is preserved across netlink attach.
#[test_log::test]
fn netlink_attach_preserves_explicit_handle() {
    let _netns = NetNsGuard::new().unwrap();

    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let handle = TcHandle::new(1, 0xfffe);

    let link_id = prog
        .attach(
            "lo",
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
    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let name = "a".repeat(len);
    let mut prog =
        SchedClassifier::from_program_info(prog.info().unwrap(), name.clone().into()).unwrap();
    let result = prog.attach(
        "lo",
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
        qdisc_detach_program("lo", TcHandle::new(0xffff, 0xfff2), &name).unwrap();
    } else {
        assert_matches!(result, Err(ProgramError::TcError(TcError::NetlinkError(err))) => {
            assert_eq!(err.to_string(), "program name exceeds CLS_BPF_NAME_LEN");
        });
    }
}
