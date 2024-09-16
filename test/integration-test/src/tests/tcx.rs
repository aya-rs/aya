use aya::{
    programs::{tc::TcAttachOptions, LinkOrder, SchedClassifier, TcAttachType},
    util::KernelVersion,
    EbpfLoader,
};
use test_log::test;

use crate::utils::NetNsGuard;

#[test(tokio::test)]
async fn tcx_attach() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 6, 0) {
        eprintln!("skipping tcx_attach test on kernel {kernel_version:?}");
        return;
    }

    let _netns = NetNsGuard::new();

    let mut program0 = EbpfLoader::new()
        .set_global("ORDER", &0, true)
        .load(crate::TCX)
        .unwrap();
    let mut program1 = EbpfLoader::new()
        .set_global("ORDER", &1, true)
        .load(crate::TCX)
        .unwrap();
    let mut program2 = EbpfLoader::new()
        .set_global("ORDER", &2, true)
        .load(crate::TCX)
        .unwrap();
    let mut program3 = EbpfLoader::new()
        .set_global("ORDER", &3, true)
        .load(crate::TCX)
        .unwrap();

    let prog0: &mut SchedClassifier = program0
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog0.load().unwrap();

    let prog1: &mut SchedClassifier = program1
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog1.load().unwrap();

    let prog2: &mut SchedClassifier = program2
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog2.load().unwrap();

    let prog3: &mut SchedClassifier = program3
        .program_mut("tcx_order")
        .unwrap()
        .try_into()
        .unwrap();
    prog3.load().unwrap();

    // Test LinkOrder::last()
    let order: LinkOrder = LinkOrder::last();
    let options = TcAttachOptions::TcxOrder(order);
    prog0
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    // Test LinkOrder::after_program()
    let order = LinkOrder::after_program(prog0).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    let prog1_link_id = prog1
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    let prog1_link = prog1.take_link(prog1_link_id).unwrap();

    // Test LinkOrder::after_link()
    let order = LinkOrder::after_link(&prog1_link).unwrap();
    let options = TcAttachOptions::TcxOrder(order);
    prog2
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();

    // Test LinkOrder::last()
    let options = TcAttachOptions::TcxOrder(LinkOrder::last());
    prog3
        .attach_with_options("lo", TcAttachType::Ingress, options)
        .unwrap();
}
