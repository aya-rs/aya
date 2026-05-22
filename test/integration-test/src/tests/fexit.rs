use aya::{
    Btf, Ebpf,
    maps::Array,
    programs::{FExit, ProgramError, ProgramType, TestRun as _},
    sys::is_program_supported,
    util::KernelVersion,
};
use aya_obj::btf::BtfError;
use integration_common::fexit::{
    ARG_MISMATCH, NO_ERROR, RETVAL_MISMATCH, TEST_RAN, TEST1_INDEX, TEST2_INDEX, TEST3_INDEX,
    TEST4_INDEX, TEST5_INDEX, TEST6_INDEX, TEST7_INDEX, TEST8_INDEX, TEST9_INDEX, TEST10_INDEX,
    TestResult,
};
use rstest::rstest;

fn fexit_error_name(error: i32) -> &'static str {
    match error {
        NO_ERROR => "NO_ERROR",
        RETVAL_MISMATCH => "RETVAL_MISMATCH",
        ARG_MISMATCH => "ARG_MISMATCH",
        _ => "HELPER_ERROR",
    }
}

// Mirrors libbpf's tracing test-run trigger:
// https://github.com/torvalds/linux/blob/v7.1-rc4/tools/testing/selftests/bpf/prog_tests/fentry_fexit.c#L24-L42
#[rstest]
#[case::test1("test1", "bpf_fentry_test1", TEST1_INDEX)]
#[case::test2("test2", "bpf_fentry_test2", TEST2_INDEX)]
#[case::test3("test3", "bpf_fentry_test3", TEST3_INDEX)]
#[case::test4("test4", "bpf_fentry_test4", TEST4_INDEX)]
#[case::test5("test5", "bpf_fentry_test5", TEST5_INDEX)]
#[case::test6("test6", "bpf_fentry_test6", TEST6_INDEX)]
#[case::test7("test7", "bpf_fentry_test7", TEST7_INDEX)]
#[case::test8("test8", "bpf_fentry_test8", TEST8_INDEX)]
#[case::test9("test9", "bpf_fentry_test9", TEST9_INDEX)]
#[case::test10("test10", "bpf_fentry_test10", TEST10_INDEX)]
fn fexit_reads_args_and_return_values_from_prog_test_run_targets(
    #[case] program: &str,
    #[case] target: &str,
    #[case] index: u32,
) {
    // The fexit program itself requires Linux 5.5, but FExitContext::ret uses
    // bpf_get_func_ret, which was added in Linux 5.17:
    // https://github.com/torvalds/linux/blob/v5.17/kernel/trace/bpf_trace.c#L1122-L1127
    // https://github.com/torvalds/linux/blob/v5.17/kernel/trace/bpf_trace.c#L1679-L1683
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 17, 0) {
        eprintln!("skipping test on kernel {kernel_version:?} - bpf_get_func_ret requires 5.17");
        return;
    }

    if !is_program_supported(ProgramType::Tracing).unwrap() {
        eprintln!("skipping test - tracing programs not supported");
        return;
    }

    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(err) => {
            eprintln!("skipping test - kernel BTF not available: {err}");
            return;
        }
    };

    let mut bpf = Ebpf::load(crate::FEXIT).unwrap();

    let mut results: Array<_, TestResult> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();
    results.set(index, TestResult::default(), 0).unwrap();

    let prog: &mut FExit = bpf.program_mut(program).unwrap().try_into().unwrap();
    match prog.load(target, &btf) {
        Ok(()) => {}
        // The kernel's tracing test-run targets have grown over time. Keep
        // older kernels useful by skipping only the case whose target is not in
        // BTF, instead of skipping the whole fexit test.
        Err(ProgramError::Btf(BtfError::UnknownBtfTypeName { type_name }))
            if type_name == target =>
        {
            eprintln!("skipping fexit target {target} - missing from kernel BTF");
            return;
        }
        Err(err) => panic!("unexpected error loading {program}: {err}"),
    }

    prog.attach().unwrap();
    // This triggers the kernel's fixed tracing test-run sequence. For FENTRY and
    // FEXIT, a successful syscall only means that sequence ran; the test-run
    // retval carries no additional result. The eBPF program checks the traced
    // function's arguments and return value through FExitContext::{arg,ret}, then
    // records the result in RESULTS.
    // https://github.com/torvalds/linux/blob/v7.1-rc4/net/bpf/test_run.c#L706-L735
    prog.test_run(()).unwrap();

    let actual = results.get(&index, 0).unwrap();
    assert_eq!(actual.ran, TEST_RAN, "{target} was not called");
    assert_eq!(
        actual.error,
        NO_ERROR,
        "{target} failed: {} ({})",
        fexit_error_name(actual.error),
        actual.error
    );
}
