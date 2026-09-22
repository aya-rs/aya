use assert_matches::assert_matches;
use aya::{
    Ebpf,
    programs::{
        Link as _, LinkOrder, ProgramError, SchedClassifier, TcAttachType,
        tc::{
            NlOptions, SchedClassifierLink, TcAttachOptions, TcError, TcHandle, qdisc_add_clsact,
            qdisc_detach_program,
        },
    },
    test_helpers::NetNsGuard,
};
use rstest::rstest;

use crate::TCX;

#[test_log::test]
fn netlink_from_parts_without_filter() {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact("lo").unwrap();

    // Reconstruction succeeds without an existing filter, but does not create one.
    let link = SchedClassifierLink::from_netlink_parts(
        "lo",
        TcAttachType::Ingress,
        1,
        TcHandle::new(0, 1),
        None,
    )
    .unwrap();
    assert_matches!(link.detach(), Err(ProgramError::NetlinkError(_)));
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
            TcAttachType::Ingress,
            NlOptions {
                classid: Some(classid),
                ..Default::default()
            },
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_eq!(link.classid().unwrap(), Some(classid));

    let new_link_id = prog.adopt_link(link).unwrap();
    let new_link = prog.take_link(new_link_id).unwrap();
    assert_eq!(new_link.classid().unwrap(), Some(classid));
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
        .attach("lo", TcAttachType::Ingress, NlOptions::default())
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
            TcAttachType::Ingress,
            NlOptions {
                handle,
                ..Default::default()
            },
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_eq!(link.handle().unwrap(), handle);
}

// The kernel's NLA_NUL_STRING limit excludes the trailing NUL. Adjacent lengths
// also exercise the padding between TCA_BPF_NAME and TCA_BPF_FLAGS.
#[rstest]
#[case::unaligned(254, true, false)]
#[case::aligned(255, true, false)]
#[case::maximum(256, true, false)]
#[case::too_long(257, false, false)]
#[case::by_index(16, true, true)]
#[test_log::test]
fn netlink_program_name(#[case] len: usize, #[case] valid: bool, #[case] by_index: bool) {
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
        TcAttachType::Ingress,
        NlOptions {
            classid: Some(TcHandle::new(1, 1)),
            ..Default::default()
        },
    );
    if valid {
        let _link = prog.take_link(result.unwrap()).unwrap();
        // Looking up the full name verifies that the kernel received it intact.
        if by_index {
            let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
            assert_ne!(index, 0);
            qdisc_detach_program(index, TcAttachType::Ingress, &name).unwrap();
        } else {
            qdisc_detach_program("lo", TcAttachType::Ingress, &name).unwrap();
        }
    } else {
        assert_matches!(result, Err(ProgramError::TcError(TcError::NetlinkError(err))) => {
            assert_eq!(err.to_string(), "program name exceeds CLS_BPF_NAME_LEN");
        });
    }
}

#[test_log::test]
fn custom_attach_uses_netlink() {
    let _netns = NetNsGuard::new().unwrap();
    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // Address the clsact ingress hook through its custom parent handle.
    let parent = TcHandle::new(0xffff, 0xfff2).into();
    let attach_type = TcAttachType::Custom(parent);
    let id = prog
        .attach("lo", attach_type, TcAttachOptions::Auto)
        .unwrap();
    let link = prog.take_link(id).unwrap();
    assert_eq!(link.attach_type().unwrap(), attach_type);
    assert_ne!(link.handle().unwrap(), TcHandle::AUTO_ASSIGN);
    link.detach().unwrap();

    assert_matches!(
        prog.attach("lo", attach_type, LinkOrder::default()),
        Err(ProgramError::TcError(TcError::InvalidTcxAttach(value))) if value == parent
    );
}
