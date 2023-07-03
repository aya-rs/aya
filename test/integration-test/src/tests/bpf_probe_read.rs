use std::process::exit;

use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{ProgramError, UProbe},
    Bpf,
};
use integration_test_macros::integration_test;

const RESULT_BUF_LEN: usize = 1024;

#[derive(Copy, Clone)]
#[repr(C)]
struct TestResult {
    did_error: u64,
    len: usize,
    buf: [u8; RESULT_BUF_LEN],
}

unsafe impl aya::Pod for TestResult {}

#[integration_test]
fn bpf_probe_read_user_str_bytes() {
    let bpf = set_user_buffer(b"foo\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"foo");
}

#[integration_test]
fn bpf_probe_read_user_str_bytes_truncate() {
    let s = vec![b'a'; RESULT_BUF_LEN];
    let bpf = set_user_buffer(&s, RESULT_BUF_LEN);
    // The kernel truncates the string and the last byte is the null terminator
    assert_eq!(result_bytes(&bpf), &s[..RESULT_BUF_LEN - 1]);
}

#[integration_test]
fn bpf_probe_read_user_str_bytes_empty_string() {
    let bpf = set_user_buffer(b"\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"");
}

#[integration_test]
fn bpf_probe_read_user_str_bytes_empty_dest() {
    let bpf = set_user_buffer(b"foo\0", 0);
    assert_eq!(result_bytes(&bpf), b"");
}

#[integration_test]
fn bpf_probe_read_kernel_str_bytes() {
    let bpf = set_kernel_buffer(b"foo\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"foo");
}

#[integration_test]
fn bpf_probe_read_kernel_str_bytes_truncate() {
    let s = vec![b'a'; RESULT_BUF_LEN];
    let bpf = set_kernel_buffer(&s, RESULT_BUF_LEN);
    // The kernel truncates the string and the last byte is the null terminator
    assert_eq!(result_bytes(&bpf), &s[..RESULT_BUF_LEN - 1]);
}

#[integration_test]
fn bpf_probe_read_kernel_str_bytes_empty_string() {
    let bpf = set_kernel_buffer(b"\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"");
}

#[integration_test]
fn bpf_probe_read_kernel_str_bytes_empty_dest() {
    let bpf = set_kernel_buffer(b"foo\0", 0);
    assert_eq!(result_bytes(&bpf), b"");
}

fn set_user_buffer(bytes: &[u8], dest_len: usize) -> Bpf {
    let bpf = load_and_attach_uprobe(
        "test_bpf_probe_read_user_str_bytes",
        "trigger_bpf_probe_read_user",
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/bpf_probe_read"),
    );
    trigger_bpf_probe_read_user(bytes.as_ptr(), dest_len);
    bpf
}

fn set_kernel_buffer(bytes: &[u8], dest_len: usize) -> Bpf {
    let mut bpf = load_and_attach_uprobe(
        "test_bpf_probe_read_kernel_str_bytes",
        "trigger_bpf_probe_read_kernel",
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/bpf_probe_read"),
    );
    set_kernel_buffer_element(&mut bpf, bytes);
    trigger_bpf_probe_read_kernel(dest_len);
    bpf
}

fn set_kernel_buffer_element(bpf: &mut Bpf, bytes: &[u8]) {
    let mut bytes = bytes.to_vec();
    bytes.resize(1024, 0xFF);
    let bytes: [u8; 1024] = bytes.try_into().unwrap();
    let mut m = Array::<_, [u8; 1024]>::try_from(bpf.map_mut("KERNEL_BUFFER").unwrap()).unwrap();
    m.set(0, bytes, 0).unwrap();
}

fn result_bytes(bpf: &Bpf) -> Vec<u8> {
    let m = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    let result = m.get(&0, 0).unwrap();
    assert!(result.did_error == 0);
    // assert that the buffer is always null terminated
    assert_eq!(result.buf[result.len], 0);
    result.buf[..result.len].to_vec()
}

fn load_and_attach_uprobe(prog_name: &str, func_name: &str, bytes: &[u8]) -> Bpf {
    let mut bpf = Bpf::load(bytes).unwrap();

    let prog: &mut UProbe = bpf.program_mut(prog_name).unwrap().try_into().unwrap();
    if let Err(ProgramError::LoadError {
        io_error,
        verifier_log,
    }) = prog.load()
    {
        println!(
            "Failed to load program `{prog_name}`: {io_error}. Verifier log:\n{verifier_log:#}"
        );
        exit(1);
    };

    prog.attach(Some(func_name), 0, "/proc/self/exe", None)
        .unwrap();

    bpf
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_bpf_probe_read_user(_string: *const u8, _len: usize) {}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_bpf_probe_read_kernel(_len: usize) {}
