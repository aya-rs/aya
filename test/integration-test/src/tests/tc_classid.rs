use aya::{
    Ebpf, TestRunOptions, TestRunResult,
    programs::{SchedClassifier, TestRun as _},
};
use integration_common::tc_classid::EXPECTED_CLASSID;

// `sizeof(pkt_v4)` = Size(Ethernet) + Size(IPv4) + Size(TCP) = 14 + 20 + 20
const PKT_V4_SIZE: usize = 14 + 20 + 20;

// The program writes `tc_classid` and returns what a subsequent read observes,
// so this asserts the store reached the field.
#[test_log::test]
fn tc_classid_set() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // BPF_PROG_TEST_RUN was introduced in v4.12 (1cf1cae963c2, "bpf: introduce
    // BPF_PROG_TEST_RUN command") with support for sched_cls (used here) and
    // sched_act program types. On kernels before v4.12 the syscall command does
    // not exist and the bpf(2) call returns EINVAL.
    if kernel_version < aya::util::KernelVersion::new(4, 12, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TC_CLASSID).unwrap();
    let prog: &mut SchedClassifier = bpf.program_mut("set_classid").unwrap().try_into().unwrap();
    prog.load().unwrap();

    // The program never reads the packet, but the kernel refuses to build the
    // skb from fewer than ETH_HLEN bytes.
    // https://github.com/torvalds/linux/blob/e5f0a698b/net/bpf/test_run.c#L662-L669
    let data_in = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        duration,
        data_size_out: _,
        ctx_size_out: _,
    } = prog.test_run(opts).unwrap();

    assert_eq!(return_value, u32::from(EXPECTED_CLASSID));
    assert!(!duration.is_zero());
}
