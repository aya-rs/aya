use aya::{
    Ebpf,
    programs::{
        SchedClassifier, TcAttachType,
        tc::{NlOptions, TcAttachOptions, TcHandle, qdisc_add_clsact},
    },
    util::KernelVersion,
};

use crate::{TCX, utils::NetNsGuard};

/// Returns true if the kernel autoloads `cls_bpf` on netlink attach.
///
/// Before kernel commit 2c15a5ae ("net/sched: Load modules via their alias",
/// released 6.10) the netlink TC code asks modprobe for `cls_bpf` by its
/// canonical name. The test-distro modprobe stub only resolves modules through
/// `modules.alias` entries, and `cls_bpf.ko` ships no self-alias, so the
/// autoload fails inside the VM. The netlink TC features themselves only
/// require 4.6.
///
/// See <https://github.com/torvalds/linux/commit/2c15a5aee2f32e341d1585fa1867eece76a1edb8>.
fn cls_bpf_autoloads() -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 10, 0) {
        eprintln!(
            "skipping on kernel {kernel_version:?}: test-distro modprobe cannot autoload cls_bpf"
        );
        return false;
    }
    true
}

/// Verify that `classid` set on the initial netlink attach is preserved when
/// the program is later replaced via [`SchedClassifier::attach_to_link`].
///
/// `cls_bpf_change` allocates a fresh `cls_bpf_prog` on every netlink replace
/// and only sets `prog->res.classid` if the request carries `TCA_BPF_CLASSID`;
/// without preservation in [`NlOptions::classid`] the binding would be
/// silently cleared on program replacement.
#[test_log::test]
fn netlink_attach_to_link_preserves_classid() {
    if !cls_bpf_autoloads() {
        return;
    }

    let _netns = NetNsGuard::new();

    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let classid = TcHandle::new(1, 1);

    let link_id = prog
        .attach_with_options(
            "lo",
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                classid: Some(classid),
                ..Default::default()
            }),
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_eq!(link.classid().unwrap(), Some(classid));

    let new_link_id = prog.attach_to_link(link).unwrap();
    let new_link = prog.take_link(new_link_id).unwrap();
    assert_eq!(new_link.classid().unwrap(), Some(classid));
}

/// Verify that [`TcHandle::AUTO_ASSIGN`] triggers kernel allocation: the
/// handle reported after attach must differ from the sentinel.
#[test_log::test]
fn netlink_attach_auto_assigns_handle() {
    if !cls_bpf_autoloads() {
        return;
    }

    let _netns = NetNsGuard::new();

    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let link_id = prog
        .attach_with_options(
            "lo",
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions::default()),
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_ne!(link.handle().unwrap(), TcHandle::AUTO_ASSIGN);
}

/// Verify that an explicit [`TcHandle`] is preserved across netlink attach.
#[test_log::test]
fn netlink_attach_preserves_explicit_handle() {
    if !cls_bpf_autoloads() {
        return;
    }

    let _netns = NetNsGuard::new();

    qdisc_add_clsact("lo").unwrap();

    let mut bpf = Ebpf::load(TCX).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("tcx_next").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let handle = TcHandle::new(1, 0xfffe);

    let link_id = prog
        .attach_with_options(
            "lo",
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                handle,
                ..Default::default()
            }),
        )
        .unwrap();

    let link = prog.take_link(link_id).unwrap();
    assert_eq!(link.handle().unwrap(), handle);
}
