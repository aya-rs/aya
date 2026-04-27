use aya::{
    Ebpf,
    programs::{
        LinkOrder, NetkitAttachType, ProgramId, SchedClassifier, tc::SchedClassifierAttachment,
    },
    util::KernelVersion,
};

use crate::utils::{NetNsGuard, create_netkit_link};

#[test_log::test]
fn netkit() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 7, 0) {
        eprintln!("skipping netkit_attach test on kernel {kernel_version:?}");
        return;
    }
    let primary = "nk-aya-0";
    let peer = "nk-aya-1";

    let _netns = NetNsGuard::new();
    if let Err(err) = create_netkit_link(primary, peer) {
        eprintln!("skipping netkit_attach test: {err}");
        return;
    }

    macro_rules! attach_program_with_link_order_inner {
        ($program_name:ident, $link_order:expr) => {
            let mut ebpf = Ebpf::load(crate::TCX).unwrap();
            let $program_name: &mut SchedClassifier =
                ebpf.program_mut("tcx_next").unwrap().try_into().unwrap();
            $program_name.load().unwrap();
        };
    }
    macro_rules! attach_program_with_link_order {
        ($program_name:ident, $link_order:expr) => {
            attach_program_with_link_order_inner!($program_name, $link_order);
            $program_name
                .attach(
                    primary,
                    SchedClassifierAttachment::Netkit {
                        attach_type: NetkitAttachType::Primary,
                        link_order: $link_order,
                    },
                )
                .unwrap();
        };
        ($program_name:ident, $link_id_name:ident, $link_order:expr) => {
            attach_program_with_link_order_inner!($program_name, $link_order);
            let $link_id_name = $program_name
                .attach(
                    primary,
                    SchedClassifierAttachment::Netkit {
                        attach_type: NetkitAttachType::Primary,
                        link_order: $link_order,
                    },
                )
                .unwrap();
        };
    }

    attach_program_with_link_order!(default, LinkOrder::default());
    attach_program_with_link_order!(first, LinkOrder::first());
    attach_program_with_link_order!(last, last_link_id, LinkOrder::last());

    let last_link = last.take_link(last_link_id).unwrap();

    attach_program_with_link_order!(before_last, LinkOrder::before_link(&last_link).unwrap());
    attach_program_with_link_order!(after_last, LinkOrder::after_link(&last_link).unwrap());

    attach_program_with_link_order!(before_default, LinkOrder::before_program(default).unwrap());
    attach_program_with_link_order!(after_default, LinkOrder::after_program(default).unwrap());

    attach_program_with_link_order!(
        before_first,
        LinkOrder::before_program_id(unsafe { ProgramId::new(first.info().unwrap().id()) })
    );
    attach_program_with_link_order!(
        after_first,
        LinkOrder::after_program_id(unsafe { ProgramId::new(first.info().unwrap().id()) })
    );

    let expected_order = [
        before_first,
        first,
        after_first,
        before_default,
        default,
        after_default,
        before_last,
        last,
        after_last,
    ]
    .iter()
    .map(|program| program.info().unwrap().id())
    .collect::<Vec<_>>();

    let (revision, got_order) =
        SchedClassifier::query_netkit(primary, NetkitAttachType::Primary).unwrap();
    assert_eq!(revision, (expected_order.len() + 1) as u64);
    assert_eq!(
        got_order
            .iter()
            .map(aya::programs::ProgramInfo::id)
            .collect::<Vec<_>>(),
        expected_order
    );
}
