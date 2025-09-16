use std::fs::File;

use aya::{Btf, Ebpf, maps::Array, programs::FEntry};
use integration_common::bpf_d_path::TestResult;

#[test_log::test]
fn bpf_d_path_basic() {
    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf = Ebpf::load(crate::BPF_D_PATH).unwrap();
    let prog: &mut FEntry = bpf
        .program_mut("test_vfs_open")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load("vfs_open", &btf).unwrap();
    prog.attach().unwrap();

    let file = File::open("/dev/null").unwrap();

    let result = get_result(&bpf);

    let path_len = result.len;
    assert!(path_len > 0, "Path length should be greater than 0");
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
