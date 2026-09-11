use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::Array,
    programs::{FExit, ProgramError, ProgramType, TestRun as _},
    sys::{BpfHelper, SyscallError, is_program_supported},
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
    let tracing_supported = is_program_supported(ProgramType::Tracing).unwrap();

    let Some(btf) = super::kernel_btf() else {
        return;
    };

    let mut bpf = Ebpf::load(crate::FEXIT).unwrap();

    let mut results: Array<_, TestResult> = bpf.take_map("RESULTS").unwrap().try_into().unwrap();
    results.set(index, &TestResult::default(), 0).unwrap();

    let prog: &mut FExit = bpf.program_mut(program).unwrap().try_into().unwrap();
    match prog.load(target, &btf) {
        Ok(()) => {}
        // Each test case uses a specific BTF target. Assert the missing target
        // that Aya actually looked up before reaching the verifier.
        Err(ProgramError::Btf(BtfError::UnknownBtfTypeName { type_name })) => {
            assert_eq!(type_name, target);
            return;
        }
        Err(error) => {
            if kernel_version < KernelVersion::new(5, 17, 0) {
                let helper_rejected = match &error {
                    ProgramError::LoadError {
                        io_error: _,
                        verifier_log,
                    } => verifier_log
                        .to_string()
                        .contains(&format!("#{}", BpfHelper::BPF_FUNC_get_func_ret as u32)),
                    _ => false,
                };
                if helper_rejected || tracing_supported {
                    super::assert_unsupported_helper(error, BpfHelper::BPF_FUNC_get_func_ret);
                    return;
                }
            }
            if !tracing_supported {
                assert_matches!(error, ProgramError::LoadError { io_error, verifier_log } => {
                    assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL), "{verifier_log}");
                    assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
                });
                return;
            }
            panic!("unexpected error loading {program}: {error}");
        }
    }

    let attached = prog.attach();
    if !tracing_supported {
        assert_matches!(attached, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
            assert_eq!(call, "bpf_raw_tracepoint_open");
            assert_eq!(io_error.raw_os_error(), Some(524));
        });
        return;
    }
    attached.unwrap();
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
