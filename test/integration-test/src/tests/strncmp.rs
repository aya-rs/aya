use std::cmp::Ordering;

use aya::{maps::Array, programs::UProbe, Bpf};

#[derive(Copy, Clone)]
#[repr(C)]
struct TestResult(Ordering);

unsafe impl aya::Pod for TestResult {}

#[test]
fn bpf_strncmp_equal() {
    let bpf = load_and_attach_uprobe();
    trigger_bpf_strncmp(b"fff".as_ptr());
    let res = fetch_result(&bpf);
    assert_eq!(res, Ordering::Equal);
}

#[test]
fn bpf_strncmp_equal_longer() {
    let bpf = load_and_attach_uprobe();
    trigger_bpf_strncmp(b"ffffff".as_ptr());
    let res = fetch_result(&bpf);
    assert_eq!(res, Ordering::Equal);
}

#[test]
fn bpf_strncmp_less() {
    let bpf = load_and_attach_uprobe();
    trigger_bpf_strncmp(b"aaa".as_ptr());
    let res = fetch_result(&bpf);
    assert_eq!(res, Ordering::Less);
}

#[test]
fn bpf_strncmp_greater() {
    let bpf = load_and_attach_uprobe();
    trigger_bpf_strncmp(b"zzz".as_ptr());
    let res = fetch_result(&bpf);
    assert_eq!(res, Ordering::Greater);
}

fn load_and_attach_uprobe() -> Bpf {
    let mut bpf = Bpf::load(crate::STRNCMP).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_bpf_strncmp")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    prog.attach(Some("trigger_bpf_strncmp"), 0, "/proc/self/exe", None)
        .unwrap();

    bpf
}

fn fetch_result(bpf: &Bpf) -> Ordering {
    let array = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();
    let TestResult(res) = array.get(&0, 0).unwrap();
    res
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_bpf_strncmp(string: *const u8) {
    core::hint::black_box(string);
}
