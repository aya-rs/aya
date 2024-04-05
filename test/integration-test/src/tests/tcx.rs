use aya::{
    programs::{tc::TcAttachOptions, LinkOrder, ProgramId, SchedClassifier, TcAttachType},
    util::KernelVersion,
    Ebpf,
};
use test_log::test;

use crate::utils::NetNsGuard;

#[test]
fn tcx() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!("skipping tcx_attach test on kernel {kernel_version:?}");
        return;
    }

    let _netns = NetNsGuard::new();

    // We need a dedicated `Ebpf` instance for each program that we load
    // since TCX does not allow the same program ID to be attached multiple
    // times to the same interface/direction.
    //
    // Variables declared within this macro are within a closure scope to avoid
    // variable name conflicts.
    //
    // Yields a tuple of the `Ebpf` which must remain in scope for the duration
    // of the test, and the link ID of the attached program.
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
                .attach_with_options(
                    "lo",
                    TcAttachType::Ingress,
                    TcAttachOptions::TcxOrder($link_order),
                )
                .unwrap();
        };
        ($program_name:ident, $link_id_name:ident, $link_order:expr) => {
            attach_program_with_link_order_inner!($program_name, $link_order);
            let $link_id_name = $program_name
                .attach_with_options(
                    "lo",
                    TcAttachType::Ingress,
                    TcAttachOptions::TcxOrder($link_order),
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

    let (revision, got_order) = SchedClassifier::query_tcx("lo", TcAttachType::Ingress).unwrap();
    assert_eq!(revision, (expected_order.len() + 1) as u64);
    assert_eq!(
        got_order.iter().map(|p| p.id()).collect::<Vec<_>>(),
        expected_order
    );
}
