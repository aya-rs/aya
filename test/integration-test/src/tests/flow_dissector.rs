use aya::{
    programs::{
        FlowDissector, ProgramError,
        flow_dissector::{FlowDissectorLink, FlowDissectorLinkId},
    },
    sys::is_program_supported,
    test_helpers::NetNsGuard,
    util::KernelVersion,
};
use aya_obj::generated::bpf_attach_type;
use rstest::rstest;

use super::{AdoptLinkProgramOps, run_adopt_link_program_test};

impl_adopt_link_program_ops!(FlowDissector, FlowDissectorLinkId, FlowDissectorLink);

#[rstest]
#[case::detach(false)]
#[case::drop(true)]
#[test_attr(test_log::test)]
fn adopt_link_flow_dissector(#[case] drop_program: bool) {
    let kernel_version = KernelVersion::current().unwrap();
    // Program-type support predates the netns links required for adoption.
    if kernel_version < KernelVersion::new(5, 8, 0)
        || !is_program_supported(FlowDissector::PROGRAM_TYPE).unwrap()
    {
        eprintln!("skipping adopt_link_flow_dissector on kernel {kernel_version:?}");
        return;
    }
    // Isolate the flow dissector attachment from other tests in its own netns.
    let netns = NetNsGuard::new().unwrap();
    run_adopt_link_program_test(
        "test_flow",
        |prog: &mut FlowDissector, netns: &NetNsGuard| prog.attach(netns).unwrap(),
        &netns,
        None,
        bpf_attach_type::BPF_FLOW_DISSECTOR,
        drop_program,
    );
}
