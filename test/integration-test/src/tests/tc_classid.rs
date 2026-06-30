use aya::{
    Ebpf, TestRunOptions, TestRunResult,
    programs::{SchedClassifier, TestRun as _},
};

const PKT_V4_SIZE: usize = 14 + 20 + 20;

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

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        ctx_size_out,
        ..
    } = prog.test_run(opts).unwrap();
    assert_eq!(return_value, 0, "Expected TC_ACT_OK(0)");
    assert_eq!(ctx_size_out, 0);
}
