use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{Array, MapType, StackTraceMap},
    programs::{Lsm, LsmAttachType, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
};
use aya_obj::btf::BtfError;
use integration_common::stack_trace::TestResult;
use rstest::rstest;

#[rstest]
#[case::legacy("STACKS_LEGACY", "RESULT_LEGACY", "record_stackid_lsm_legacy")]
#[case::btf("STACKS", "RESULT", "record_stackid_lsm")]
#[test_attr(test_log::test)]
fn record_stackid_lsm(#[case] stacks_map: &str, #[case] result_map: &str, #[case] prog: &str) {
    let missing =
        super::unsupported_map_names([(MapType::StackTrace, &["STACKS", "STACKS_LEGACY"][..])]);
    let Some(mut bpf) =
        super::map_load_or_expect_unsupported(Ebpf::load(crate::STACK_TRACE_LSM), &missing)
    else {
        return;
    };

    let Some(btf) = super::kernel_btf() else {
        return;
    };
    {
        let mut target_tgid: Array<_, u32> =
            Array::try_from(bpf.map_mut("TARGET_TGID").unwrap()).unwrap();
        target_tgid.set(0, &std::process::id(), 0).unwrap();
    }
    let lsm_supported = is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap();
    let link_id = {
        let lsm: &mut Lsm = bpf
            .program_mut(prog)
            .unwrap_or_else(|| panic!("missing program {prog}"))
            .try_into()
            .unwrap();
        let load_result = lsm.load("socket_bind", &btf);
        if !lsm_supported {
            match load_result {
                Ok(()) => {
                    assert_matches!(lsm.attach(), Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                        assert_eq!(call, "bpf_raw_tracepoint_open");
                        assert_eq!(io_error.raw_os_error(), Some(524));
                    });
                }
                Err(ProgramError::Btf(BtfError::UnknownBtfTypeName { type_name })) => {
                    assert_eq!(type_name, "bpf_lsm_socket_bind");
                }
                Err(ProgramError::LoadError {
                    io_error,
                    verifier_log,
                }) => {
                    assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                    assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
                }
                Err(error) => panic!("unexpected LSM program failure: {error}"),
            }
            return;
        }
        load_result.unwrap();
        lsm.attach().unwrap()
    };

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

    // A loaded and attached LSM program only receives hooks while the BPF LSM
    // module is active.
    let bpf_lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .split(',')
        .any(|module| module.trim() == "bpf");

    let result = Array::<_, TestResult>::try_from(bpf.map(result_map).unwrap()).unwrap();
    let TestResult { stack_id, ran } = result.get(&0, 0).unwrap();
    if bpf_lsm_active {
        assert!(ran, "LSM probe {prog} did not run");

        let stacks = StackTraceMap::try_from(bpf.map(stacks_map).unwrap()).unwrap();
        let trace = stacks
            .get(&stack_id, 0)
            .expect("stack_id not found in stack trace map");
        let frames = trace.frames();
        assert!(
            frames.iter().any(|f| f.ip != 0),
            "stack trace for stack_id {stack_id} has no non-zero IP frame; got {} frames",
            frames.len(),
        );
    } else {
        assert!(!ran, "LSM probe {prog} ran without the BPF LSM module");
        assert_eq!(stack_id, 0, "inactive LSM wrote a stack ID");
    }
    drop(listener);

    let lsm: &mut Lsm = bpf.program_mut(prog).unwrap().try_into().unwrap();
    lsm.detach(link_id).unwrap();
}
