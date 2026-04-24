use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    maps::{Array, MapType, StackTraceMap},
    programs::{Lsm, LsmAttachType, ProgramError, ProgramType},
    sys::{SyscallError, is_map_supported, is_program_supported},
};
use integration_common::stack_trace::TestResult;

#[test]
fn record_stackid_lsm() {
    if !is_map_supported(MapType::StackTrace).unwrap() {
        eprintln!("skipping test - stack trace map not supported");
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf: Ebpf = Ebpf::load(crate::STACK_TRACE_LSM).unwrap();
    {
        let mut target_tgid: Array<_, u32> =
            Array::try_from(bpf.map_mut("TARGET_TGID").unwrap()).unwrap();
        target_tgid.set(0, std::process::id(), 0).unwrap();
    }
    let link_id = {
        let prog: &mut Lsm = bpf
            .program_mut("record_stackid_lsm")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load("socket_bind", &btf).unwrap();
        let result = prog.attach();
        if !is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap() {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            eprintln!("skipping test - LSM programs not supported");
            return;
        }
        result.unwrap()
    };

    std::net::TcpListener::bind("127.0.0.1:0").unwrap();

    // The BPF LSM module is only active on kernels booted with `lsm=bpf`.
    // Attach succeeds either way (`is_program_supported` only requires
    // `CONFIG_BPF_LSM=y`), but the hook only fires when the module is live.
    if !std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .contains("bpf")
    {
        eprintln!("skipping runtime assertions - BPF LSM not active");
        return;
    }

    let result = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    let TestResult { stack_id, ran } = result.get(&0, 0).unwrap();
    assert!(ran, "LSM probe did not run");

    let stacks = StackTraceMap::try_from(bpf.map("STACKS").unwrap()).unwrap();
    let trace = stacks
        .get(&stack_id, 0)
        .expect("stack_id not found in stack trace map");
    let frames = trace.frames();
    assert!(
        frames.iter().any(|f| f.ip != 0),
        "stack trace for stack_id {stack_id} has no non-zero IP frame; got {} frames",
        frames.len(),
    );

    let prog: &mut Lsm = bpf
        .program_mut("record_stackid_lsm")
        .unwrap()
        .try_into()
        .unwrap();
    prog.detach(link_id).unwrap();
}
