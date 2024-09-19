use aya::{
    programs::{tc::TcAttachOptions, LinkOrder, ProgramId, SchedClassifier, TcAttachType},
    util::KernelVersion,
    Ebpf,
};
use test_log::test;

use crate::utils::NetNsGuard;

#[test(tokio::test)]
async fn tcx() {
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
    macro_rules! attach_program_with_linkorder {
        ($link_order:expr) => {{
            let mut ebpf = Ebpf::load(crate::TCX).unwrap();
            let program: &mut SchedClassifier =
                ebpf.program_mut("tcx_next").unwrap().try_into().unwrap();
            program.load().unwrap();
            let link_id = program
                .attach_with_options(
                    "lo",
                    TcAttachType::Ingress,
                    TcAttachOptions::TcxOrder($link_order),
                )
                .unwrap();
            (ebpf, link_id)
        }};
    }

    let (default, _) = attach_program_with_linkorder!(LinkOrder::default());
    let (first, _) = attach_program_with_linkorder!(LinkOrder::first());
    let (mut last, last_link_id) = attach_program_with_linkorder!(LinkOrder::last());

    let default_prog: &SchedClassifier = default.program("tcx_next").unwrap().try_into().unwrap();
    let first_prog: &SchedClassifier = first.program("tcx_next").unwrap().try_into().unwrap();
    let last_prog: &mut SchedClassifier = last.program_mut("tcx_next").unwrap().try_into().unwrap();

    let last_link = last_prog.take_link(last_link_id).unwrap();

    let (before_last, _) =
        attach_program_with_linkorder!(LinkOrder::before_link(&last_link).unwrap());
    let (after_last, _) =
        attach_program_with_linkorder!(LinkOrder::after_link(&last_link).unwrap());

    let (before_default, _) =
        attach_program_with_linkorder!(LinkOrder::before_program(default_prog).unwrap());
    let (after_default, _) =
        attach_program_with_linkorder!(LinkOrder::after_program(default_prog).unwrap());

    let (before_first, _) = attach_program_with_linkorder!(LinkOrder::before_program_id(unsafe {
        ProgramId::new(first_prog.info().unwrap().id())
    }));
    let (after_first, _) = attach_program_with_linkorder!(LinkOrder::after_program_id(unsafe {
        ProgramId::new(first_prog.info().unwrap().id())
    }));

    let expected_order = [
        before_first
            .program("tcx_next")
            .unwrap()
            .info()
            .unwrap()
            .id(),
        first_prog.info().unwrap().id(),
        after_first
            .program("tcx_next")
            .unwrap()
            .info()
            .unwrap()
            .id(),
        before_default
            .program("tcx_next")
            .unwrap()
            .info()
            .unwrap()
            .id(),
        default_prog.info().unwrap().id(),
        after_default
            .program("tcx_next")
            .unwrap()
            .info()
            .unwrap()
            .id(),
        before_last
            .program("tcx_next")
            .unwrap()
            .info()
            .unwrap()
            .id(),
        last_prog.info().unwrap().id(),
        after_last.program("tcx_next").unwrap().info().unwrap().id(),
    ];

    let (revision, got_order) = SchedClassifier::query_tcx("lo", TcAttachType::Ingress).unwrap();
    assert_eq!(revision, (expected_order.len() + 1) as u64);
    assert_eq!(
        got_order.iter().map(|p| p.id()).collect::<Vec<_>>(),
        expected_order
    );
}
