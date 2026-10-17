use std::{fmt::Debug, fs::File};

use assert_matches::assert_matches;
use aya::{
    Ebpf,
    programs::{
        CgroupAttachMode, CgroupDevice, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr,
        CgroupSockopt, CgroupSysctl, Link, Program, ProgramError, SockOps,
        cgroup_device::{CgroupDeviceLink, CgroupDeviceLinkId},
        cgroup_skb::{CgroupSkbLink, CgroupSkbLinkId},
        cgroup_sock::{CgroupSockLink, CgroupSockLinkId},
        cgroup_sock_addr::{CgroupSockAddrLink, CgroupSockAddrLinkId},
        cgroup_sockopt::{CgroupSockoptLink, CgroupSockoptLinkId},
        cgroup_sysctl::{CgroupSysctlLink, CgroupSysctlLinkId},
        links::LinkError,
        sock_ops::{SockOpsLink, SockOpsLinkId},
    },
    sys::is_program_supported,
    test_helpers::{Cgroup, with_legacy_cgroup_links},
    util::KernelVersion,
};
use aya_obj::generated::bpf_attach_type;
use rstest::rstest;

use super::{AdoptLinkProgramOps, attached_program, run_adopt_link_program_test};

impl_adopt_link_program_ops!(CgroupDevice, CgroupDeviceLinkId, CgroupDeviceLink);
impl_adopt_link_program_ops!(CgroupSkb, CgroupSkbLinkId, CgroupSkbLink);
impl_adopt_link_program_ops!(CgroupSock, CgroupSockLinkId, CgroupSockLink);
impl_adopt_link_program_ops!(CgroupSockAddr, CgroupSockAddrLinkId, CgroupSockAddrLink);
impl_adopt_link_program_ops!(CgroupSockopt, CgroupSockoptLinkId, CgroupSockoptLink);
impl_adopt_link_program_ops!(CgroupSysctl, CgroupSysctlLinkId, CgroupSysctlLink);
impl_adopt_link_program_ops!(SockOps, SockOpsLinkId, SockOpsLink);

// Every type covers adoption with an existing attachment and explicit detach;
// CgroupSkb also covers shared program-drop cleanup.
#[rstest]
#[case::device(
    "test_device",
    |prog: &mut CgroupDevice, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_DEVICE,
    false,
)]
#[case::skb_detach(
    "test_cgroup_skb",
    |prog: &mut CgroupSkb, fd: &File| {
        prog.attach(fd, CgroupSkbAttachType::Egress, CgroupAttachMode::Single).unwrap()
    },
    bpf_attach_type::BPF_CGROUP_INET_EGRESS,
    false,
)]
#[case::skb_drop(
    "test_cgroup_skb",
    |prog: &mut CgroupSkb, fd: &File| {
        prog.attach(fd, CgroupSkbAttachType::Egress, CgroupAttachMode::Single).unwrap()
    },
    bpf_attach_type::BPF_CGROUP_INET_EGRESS,
    true,
)]
#[case::sock(
    "test_sock",
    |prog: &mut CgroupSock, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_INET_SOCK_CREATE,
    false,
)]
#[case::sock_addr(
    "test_sock_addr",
    |prog: &mut CgroupSockAddr, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_INET4_CONNECT,
    false,
)]
#[case::sockopt(
    "test_sockopt",
    |prog: &mut CgroupSockopt, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_GETSOCKOPT,
    false,
)]
#[case::sysctl(
    "test_sysctl",
    |prog: &mut CgroupSysctl, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_SYSCTL,
    false,
)]
#[case::sock_ops(
    "test_sock_ops",
    |prog: &mut SockOps, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_SOCK_OPS,
    false,
)]
#[test_attr(test_log::test)]
fn adopt_link_cgroup<P>(
    #[case] program_name: &str,
    #[case] attach: fn(&mut P, &File) -> P::LinkId,
    #[case] attach_type: bpf_attach_type,
    #[case] drop_program: bool,
) where
    P: AdoptLinkProgramOps,
    P::OwnedLink: Debug,
    for<'a> &'a mut Program: TryInto<&'a mut P, Error = ProgramError>,
{
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 7, 0)
        || !is_program_supported(P::PROGRAM_TYPE).unwrap()
    {
        eprintln!("skipping adopt_link_cgroup for {program_name} on kernel {kernel_version:?}");
        return;
    }
    let root = Cgroup::root().unwrap();
    let cgroup = root
        .create_child(&format!("{program_name}-{drop_program}"))
        .unwrap();
    let existing_cgroup = root
        .create_child(&format!("{program_name}-{drop_program}-existing"))
        .unwrap();
    let cgroup_fd = cgroup.fd().unwrap();
    let existing_cgroup_fd = existing_cgroup.fd().unwrap();
    run_adopt_link_program_test(
        program_name,
        attach,
        &cgroup_fd,
        Some(&existing_cgroup_fd),
        attach_type,
        drop_program,
    );
}

#[rstest]
#[case::matching(CgroupSkbAttachType::Egress, true)]
#[case::mismatched(CgroupSkbAttachType::Ingress, false)]
#[test_attr(test_log::test)]
fn adopt_link_cgroup_skb_checks_actual_attach_type(
    #[case] attach_type: CgroupSkbAttachType,
    #[case] compatible: bool,
) {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 7, 0) {
        eprintln!(
            "skipping adopt_link_cgroup_skb_checks_actual_attach_type on kernel {kernel_version:?}"
        );
        return;
    }
    let root = Cgroup::root().unwrap();
    let cgroup = root
        .create_child(&format!("aya-adopt-skb-{compatible}"))
        .unwrap();
    let cgroup_fd = cgroup.fd().unwrap();
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let generic: &mut CgroupSkb = bpf
        .program_mut("test_cgroup_skb_generic")
        .unwrap()
        .try_into()
        .unwrap();
    generic.load().unwrap();
    let old_program_id = generic.info().unwrap().id();
    assert!(generic.expected_attach_type().is_none());
    let id = generic
        .attach(&cgroup_fd, attach_type, CgroupAttachMode::Single)
        .unwrap();
    let link = generic.take_link(id).unwrap();

    // A generic program can adopt either hook. This update must preserve the
    // link's actual attach type for a subsequent adoption by a specific program.
    let id = generic.adopt_link(link).unwrap();
    let link = generic.take_link(id).unwrap();
    let link_id = link.id();
    let mut new_bpf = Ebpf::load(crate::TEST).unwrap();
    let egress: &mut CgroupSkb = new_bpf
        .program_mut("test_cgroup_skb")
        .unwrap()
        .try_into()
        .unwrap();
    egress.load().unwrap();
    let result = egress.adopt_link(link);
    if compatible {
        assert_eq!(
            attached_program(&cgroup_fd, attach_type),
            Some(egress.info().unwrap().id()),
        );
        egress.detach(result.unwrap()).unwrap();
    } else {
        let (error, link) = result.unwrap_err();
        assert_matches!(error, ProgramError::LinkError(LinkError::InvalidLink));
        assert_eq!(link.id(), link_id);
        assert_eq!(
            attached_program(&cgroup_fd, attach_type),
            Some(old_program_id)
        );

        // The rejected link must remain usable by a compatible replacement.
        let replacement: &mut CgroupSkb = new_bpf
            .program_mut("test_cgroup_skb_generic")
            .unwrap()
            .try_into()
            .unwrap();
        replacement.load().unwrap();
        let new_program_id = replacement.info().unwrap().id();
        assert_ne!(old_program_id, new_program_id);
        let id = replacement.adopt_link(link).unwrap();
        assert_eq!(
            attached_program(&cgroup_fd, attach_type),
            Some(new_program_id)
        );
        replacement.detach(id).unwrap();
    }
    assert_eq!(attached_program(&cgroup_fd, attach_type), None);
}

// Cover every program type with a BPF_PROG_ATTACH backend. LSM cgroup programs
// always use BPF links and have separate tests in lsm.rs.
#[rstest]
#[case::device(
    "test_device",
    |prog: &mut CgroupDevice, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_DEVICE,
)]
#[case::skb(
    "test_cgroup_skb_generic",
    |prog: &mut CgroupSkb, fd: &File| {
        prog.attach(fd, CgroupSkbAttachType::Egress, CgroupAttachMode::Single).unwrap()
    },
    bpf_attach_type::BPF_CGROUP_INET_EGRESS,
)]
#[case::sock(
    "test_sock",
    |prog: &mut CgroupSock, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_INET_SOCK_CREATE,
)]
#[case::sock_addr(
    "test_sock_addr",
    |prog: &mut CgroupSockAddr, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_INET4_CONNECT,
)]
#[case::sockopt(
    "test_sockopt",
    |prog: &mut CgroupSockopt, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_GETSOCKOPT,
)]
#[case::sysctl(
    "test_sysctl",
    |prog: &mut CgroupSysctl, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_SYSCTL,
)]
#[case::sock_ops(
    "test_sock_ops",
    |prog: &mut SockOps, fd: &File| prog.attach(fd, CgroupAttachMode::Single).unwrap(),
    bpf_attach_type::BPF_CGROUP_SOCK_OPS,
)]
#[test_attr(test_log::test)]
fn adopt_link_legacy_cgroup_returns_link<P>(
    #[case] program_name: &str,
    #[case] attach: fn(&mut P, &File) -> P::LinkId,
    #[case] attach_type: bpf_attach_type,
) where
    P: AdoptLinkProgramOps,
    P::LinkId: Debug + PartialEq,
    P::OwnedLink: Link<Id = P::LinkId, Error = ProgramError>,
    for<'a> &'a mut Program: TryInto<&'a mut P, Error = ProgramError>,
{
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(4, 15, 0)
        || !is_program_supported(P::PROGRAM_TYPE).unwrap()
    {
        eprintln!(
            "skipping adopt_link_legacy_cgroup_returns_link for {program_name} on kernel {kernel_version:?}"
        );
        return;
    }
    let root = Cgroup::root().unwrap();
    let cgroup = root
        .create_child(&format!("aya-adopt-legacy-{program_name}"))
        .unwrap();
    let cgroup_fd = cgroup.fd().unwrap();
    let mut bpf = Ebpf::load(crate::TEST).unwrap();
    let old: &mut P = bpf.program_mut(program_name).unwrap().try_into().unwrap();
    old.load().unwrap();
    let id = with_legacy_cgroup_links(|| attach(old, &cgroup_fd));
    let link = old.take_link(id).unwrap();
    let id = link.id();
    let old_program_id = bpf.program(program_name).unwrap().info().unwrap().id();
    let mut new_bpf = Ebpf::load(crate::TEST).unwrap();
    let new: &mut P = new_bpf
        .program_mut(program_name)
        .unwrap()
        .try_into()
        .unwrap();
    new.load().unwrap();

    let (error, link) = new.adopt_link(link).unwrap_err();
    assert_matches!(error, ProgramError::LinkError(LinkError::InvalidLink));
    assert_eq!(link.id(), id);
    assert_matches!(new.take_link(id), Err(ProgramError::NotAttached));
    assert_eq!(
        attached_program(&cgroup_fd, attach_type),
        Some(old_program_id)
    );
    link.detach().unwrap();
    assert_eq!(attached_program(&cgroup_fd, attach_type), None);
}
