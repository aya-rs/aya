use aya::{maps::Array, programs::UProbe, Ebpf};
use test_log::test;

const RESULT_BUF_LEN: usize = 1024;

#[derive(Copy, Clone)]
#[repr(C)]
struct TestResult {
    buf: [u8; RESULT_BUF_LEN],
    len: Option<Result<usize, i64>>,
}

unsafe impl aya::Pod for TestResult {}

#[test]
fn bpf_probe_read_user_str_bytes() {
    let bpf = set_user_buffer(b"foo\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"foo");
}

#[test]
fn bpf_probe_read_user_str_bytes_truncate() {
    let s = vec![b'a'; RESULT_BUF_LEN];
    let bpf = set_user_buffer(&s, RESULT_BUF_LEN);
    // The kernel truncates the string and the last byte is the null terminator
    assert_eq!(result_bytes(&bpf), &s[..RESULT_BUF_LEN - 1]);
}

#[test]
fn bpf_probe_read_user_str_bytes_empty_string() {
    let bpf = set_user_buffer(b"\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"");
}

#[test]
fn bpf_probe_read_user_str_bytes_empty_dest() {
    let bpf = set_user_buffer(b"foo\0", 0);
    assert_eq!(result_bytes(&bpf), b"");
}

#[test]
fn bpf_probe_read_kernel_str_bytes() {
    let bpf = set_kernel_buffer(b"foo\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"foo");
}

#[test]
fn bpf_probe_read_kernel_str_bytes_truncate() {
    let s = vec![b'a'; RESULT_BUF_LEN];
    let bpf = set_kernel_buffer(&s, RESULT_BUF_LEN);
    // The kernel truncates the string and the last byte is the null terminator
    assert_eq!(result_bytes(&bpf), &s[..RESULT_BUF_LEN - 1]);
}

#[test]
fn bpf_probe_read_kernel_str_bytes_empty_string() {
    let bpf = set_kernel_buffer(b"\0", RESULT_BUF_LEN);
    assert_eq!(result_bytes(&bpf), b"");
}

#[test]
fn bpf_probe_read_kernel_str_bytes_empty_dest() {
    let bpf = set_kernel_buffer(b"foo\0", 0);
    assert_eq!(result_bytes(&bpf), b"");
}

fn set_user_buffer(bytes: &[u8], dest_len: usize) -> Ebpf {
    let bpf = load_and_attach_uprobe(
        "test_bpf_probe_read_user_str_bytes",
        "trigger_bpf_probe_read_user",
        crate::BPF_PROBE_READ,
    );
    trigger_bpf_probe_read_user(bytes.as_ptr(), dest_len);
    bpf
}

fn set_kernel_buffer(bytes: &[u8], dest_len: usize) -> Ebpf {
    let mut bpf = load_and_attach_uprobe(
        "test_bpf_probe_read_kernel_str_bytes",
        "trigger_bpf_probe_read_kernel",
        crate::BPF_PROBE_READ,
    );
    set_kernel_buffer_element(&mut bpf, bytes);
    trigger_bpf_probe_read_kernel(dest_len);
    bpf
}

fn set_kernel_buffer_element(bpf: &mut Ebpf, bytes: &[u8]) {
    let mut bytes = bytes.to_vec();
    bytes.resize(1024, 0xFF);
    let bytes: [u8; 1024] = bytes.try_into().unwrap();
    let mut m = Array::<_, [u8; 1024]>::try_from(bpf.map_mut("KERNEL_BUFFER").unwrap()).unwrap();
    m.set(0, bytes, 0).unwrap();
}

#[track_caller]
fn result_bytes(bpf: &Ebpf) -> Vec<u8> {
    let m = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    let TestResult { buf, len } = m.get(&0, 0).unwrap();
    let len = len.unwrap();
    let len = len.unwrap();
    // assert that the buffer is always null terminated
    assert_eq!(buf[len], 0);
    buf[..len].to_vec()
}

fn load_and_attach_uprobe(prog_name: &str, func_name: &str, bytes: &[u8]) -> Ebpf {
    let mut bpf = Ebpf::load(bytes).unwrap();

    let prog: &mut UProbe = bpf.program_mut(prog_name).unwrap().try_into().unwrap();
    prog.load().unwrap();

    prog.attach(Some(func_name), 0, "/proc/self/exe", None)
        .unwrap();

    bpf
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_bpf_probe_read_user(string: *const u8, len: usize) {
    core::hint::black_box((string, len));
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_bpf_probe_read_kernel(len: usize) {
    core::hint::black_box(len);
}
