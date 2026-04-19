use assert_matches::assert_matches;
use std::fs::File;

use aya::{
    Btf, Ebpf,
    maps::Array,
    programs::{FEntry, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
};
use integration_common::bpf_d_path::TestResult;

#[test_log::test]
fn bpf_d_path_basic() {
    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf = Ebpf::load(crate::BPF_D_PATH).unwrap();

    {
        let mut pid_map = Array::<_, u32>::try_from(bpf.map_mut("PID").unwrap()).unwrap();
        pid_map.set(0, std::process::id(), 0).unwrap();
    }
    {
        let mut result_map =
            Array::<_, TestResult>::try_from(bpf.map_mut("RESULT").unwrap()).unwrap();
        result_map
            .set(
                0,
                TestResult {
                    buf: [0; integration_common::bpf_d_path::PATH_BUF_LEN],
                    len: 0,
                },
                0,
            )
            .unwrap();
    }

    let prog: &mut FEntry = bpf
        .program_mut("test_dentry_open")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load("dentry_open", &btf).unwrap();
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

    let file = File::open("/dev/null").unwrap();

    let result = get_result(&bpf);

    let path_len = result.len;
    assert!(
        path_len > 0,
        "Path length should be greater than 0. If it's 0, the BPF program might not have been triggered for this PID ({}) by File::open() or bpf_d_path failed.",
        std::process::id()
    );
    assert!(
        path_len <= result.buf.len(),
        "Path length should not exceed buffer size"
    );

    let path_str = std::str::from_utf8(&result.buf[..path_len]).unwrap();
    assert!(
        path_str.contains("/dev/null"),
        "Path should contain '/dev/null', got: {}",
        path_str
    );

    drop(file);
}

fn get_result(bpf: &Ebpf) -> TestResult {
    let m = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    m.get(&0, 0).unwrap()
}
