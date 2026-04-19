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
        let mut tid_map = Array::<_, u32>::try_from(bpf.map_mut("TID").unwrap()).unwrap();
        let tid = u32::try_from(nix::unistd::gettid().as_raw()).unwrap();
        tid_map.set(0, tid, 0).unwrap();
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
                    seen: 0,
                    status: 0,
                },
                0,
            )
            .unwrap();
    }

    let prog: &mut FEntry = bpf
        .program_mut("test_vfs_open")
        .unwrap()
        .try_into()
        .unwrap();
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

    let file = File::open("/dev/null").unwrap();

    let result = get_result(&bpf);

    assert!(
        result.seen > 0,
        "The BPF program did not observe any matching vfs_open() call for this test thread (tid {}).",
        nix::unistd::gettid()
    );
    assert_eq!(
        result.status, 0,
        "bpf_d_path failed in the BPF program with status {}",
        result.status
    );

    let path_len = result.len;
    assert!(
        path_len > 0,
        "Path length should be greater than 0 after a successful bpf_d_path call for tid {}.",
        nix::unistd::gettid(),
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
