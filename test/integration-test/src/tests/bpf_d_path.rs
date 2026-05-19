use std::fs::File;

use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::Array,
    programs::{FEntry, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
    util::KernelVersion,
};
use integration_common::bpf_d_path::{EXPECTED_PATH, TestResult};

#[test_log::test]
fn bpf_d_path_basic() {
    let kernel_version = KernelVersion::current().unwrap();
    let min_version = if cfg!(target_arch = "aarch64") {
        KernelVersion::new(6, 4, 0)
    } else {
        KernelVersion::new(5, 11, 0)
    };
    // Sleepable fentry programs (required for bpf_d_path) are supported from kernel 5.11+
    // See: commit adding BPF_F_SLEEPABLE support for tracing programs
    if kernel_version < min_version {
        eprintln!(
            "skipping test on kernel {kernel_version:?} - sleepable fentry programs (required for bpf_d_path) are not supported"
        );
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    let pid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_PID", &pid, true)
        .load(crate::BPF_D_PATH)
        .unwrap();

    let prog: &mut FEntry = bpf
        .program_mut("test_vfs_open")
        .unwrap()
        .try_into()
        .unwrap();
    // Load the fentry program; on kernels < 5.11 (x86_64) or < 6.4 (aarch64), sleepable fentry is not supported.
    prog.load("vfs_open", &btf).unwrap();
    let _link_id = {
        let result = prog.attach();
        if !is_program_supported(ProgramType::Tracing).unwrap() {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            eprintln!("skipping test - tracing programs not supported at attach");
            return;
        }
        result.unwrap()
    };

    let file = File::open(EXPECTED_PATH).unwrap();

    let result = get_result(&bpf);

    assert!(
        result.seen > 0,
        "The BPF program did not observe any matching vfs_open() call for this test process (pid {pid}).",
    );
    assert_eq!(
        result.status, 0,
        "bpf_d_path failed in the BPF program with status {}",
        result.status
    );

    assert!(
        result.len <= result.buf.len(),
        "Path length should not exceed buffer size"
    );

    let path_str = std::str::from_utf8(&result.buf[..result.len]).unwrap();
    assert_eq!(
        path_str, EXPECTED_PATH,
        "unexpected path returned by bpf_d_path"
    );

    drop(file);
}

fn get_result(bpf: &Ebpf) -> TestResult {
    let m = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    m.get(&0, 0).unwrap()
}
