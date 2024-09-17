use std::collections::HashMap;

use aya::{
    programs::{
        tc::{SchedClassifierLink, TcAttachOptions},
        LinkOrder, ProgramId, SchedClassifier, TcAttachType,
    },
    util::KernelVersion,
    Ebpf, EbpfLoader,
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
    let mut attached_programs: HashMap<&str, (Ebpf, SchedClassifierLink)> = HashMap::new();
    macro_rules! attach_program_with_linkorder {
        ($name:literal,$link_order:expr) => {{
            let mut loader = EbpfLoader::new().load(crate::TCX).unwrap();
            let program: &mut SchedClassifier =
                loader.program_mut("tcx_next").unwrap().try_into().unwrap();
            program.load().unwrap();
            let options = TcAttachOptions::TcxOrder($link_order);
            let link_id = program
                .attach_with_options("lo", TcAttachType::Ingress, options)
                .unwrap();
            let link = program.take_link(link_id).unwrap();
            attached_programs.insert($name, (loader, link));
        }};
    }

    // TODO: Assert in position 4 at the end of the test.
    attach_program_with_linkorder!("default", LinkOrder::default());
    // TODO: Assert in position 1 at the end of the test.
    attach_program_with_linkorder!("first", LinkOrder::first());
    // TODO: Assert in position 7 at the end of the test.
    attach_program_with_linkorder!("last", LinkOrder::last());
    // TODO: Assert in position 6 at the end of the test.
    attach_program_with_linkorder!(
        "before_last",
        LinkOrder::before_link(&attached_programs.get("last").unwrap().1).unwrap()
    );
    // TODO: Assert in position 8 at the end of the test.
    attach_program_with_linkorder!(
        "after_last",
        LinkOrder::after_link(&attached_programs.get("last").unwrap().1).unwrap()
    );
    // TODO: Assert in position 3 at the end of the test.
    attach_program_with_linkorder!(
        "before_default",
        LinkOrder::before_program(
            TryInto::<&SchedClassifier>::try_into(
                attached_programs
                    .get("default")
                    .unwrap()
                    .0
                    .program("tcx_next")
                    .unwrap(),
            )
            .unwrap()
        )
        .unwrap()
    );
    // TODO: Assert in position 5 at the end of the test.
    attach_program_with_linkorder!(
        "after_default",
        LinkOrder::after_program(
            TryInto::<&SchedClassifier>::try_into(
                attached_programs
                    .get("default")
                    .unwrap()
                    .0
                    .program("tcx_next")
                    .unwrap(),
            )
            .unwrap()
        )
        .unwrap()
    );
    // TODO: Assert in position 0 at the end of the test.
    attach_program_with_linkorder!(
        "before_first",
        LinkOrder::before_program_id(unsafe {
            ProgramId::new(
                TryInto::<&SchedClassifier>::try_into(
                    attached_programs
                        .get("first")
                        .unwrap()
                        .0
                        .program("tcx_next")
                        .unwrap(),
                )
                .unwrap()
                .info()
                .unwrap()
                .id(),
            )
        })
    );
    // TODO: Assert in position 2 at the end of the test.
    attach_program_with_linkorder!(
        "after_first",
        LinkOrder::after_program_id(unsafe {
            ProgramId::new(
                TryInto::<&SchedClassifier>::try_into(
                    attached_programs
                        .get("first")
                        .unwrap()
                        .0
                        .program("tcx_next")
                        .unwrap(),
                )
                .unwrap()
                .info()
                .unwrap()
                .id(),
            )
        })
    );
    // TODO: Add code here to automatically verify the order after the API based
    // on the BPF_PROG_QUERY syscall is implemented.
}
