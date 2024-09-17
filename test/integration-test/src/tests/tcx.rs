use aya::{
    programs::{
        tc::{SchedClassifierLink, TcAttachOptions},
        Link, LinkOrder, ProgramId, SchedClassifier, TcAttachType,
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

    // Create 9 programs for testing the 9 different LinkOrder constructors.
    let mut programs: Vec<Ebpf> = vec![];
    for _ in 0..9 {
        let program = EbpfLoader::new().load(crate::TCX).unwrap();
        programs.push(program);
    }

    let mut tcx_programs: Vec<&mut SchedClassifier> = vec![];
    for program in programs.iter_mut() {
        let prog: &mut SchedClassifier =
            program.program_mut("tcx_next").unwrap().try_into().unwrap();
        prog.load().unwrap();
        tcx_programs.push(prog);
    }

    let mut tcx_links: Vec<SchedClassifierLink> = vec![];

    // Test LinkOrder::default()
    // Should end up in position 4 at the end of the test.
    let order = LinkOrder::default();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[0]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[0].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::first()
    // Should end up in position 1 at the end of the test.
    let order: LinkOrder = LinkOrder::first();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[1]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[1].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::last()
    // Should end up in position 7 at the end of the test.
    let order: LinkOrder = LinkOrder::last();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[2]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[2].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::before_link()
    // Should end up in position 6 at the end of the test.
    let order = LinkOrder::before_link(&tcx_links[2]).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[3]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[3].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::after_link()
    // Should end up in position 8 at the end of the test.
    let order = LinkOrder::after_link(&tcx_links[2]).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[4]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[4].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::before_program()
    // Should end up in position 3 at the end of the test.
    let order = LinkOrder::before_program(tcx_programs[0]).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[5]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[5].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::after_program()
    // Should end up in position 5 at the end of the test.
    let order = LinkOrder::after_program(tcx_programs[0]).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[6]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[6].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::before_program_id()
    // Should end up in position 0 at the end of the test.
    let prog_1_id = unsafe { ProgramId::new(tcx_programs[1].info().unwrap().id()) };
    let order = LinkOrder::before_program_id(prog_1_id);
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[7]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[7].take_link(link_id).unwrap();
    tcx_links.push(link);

    // Test LinkOrder::after_program_id()
    // Should end up in position 2 at the end of the test.
    let prog_1_id = unsafe { ProgramId::new(tcx_programs[1].info().unwrap().id()) };
    let order = LinkOrder::after_program_id(prog_1_id);
    let options = TcAttachOptions::TcxOrder(order);
    let link_id = tcx_programs[8]
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
    let link = tcx_programs[8].take_link(link_id).unwrap();
    tcx_links.push(link);

    // It as been manually verified that all the programs are attached in the
    // correct order.
    // TODO: Add code here to automatically verify the order after the API based
    // on the BPF_PROG_QUERY syscall is implemented.

    // Detach all links
    while let Some(link) = tcx_links.pop() {
        link.detach().unwrap();
    }

    // Unload all programs
    for program in tcx_programs {
        program.unload().unwrap();
    }
}
