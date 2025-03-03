use std::{
    cmp::Ordering,
    ffi::{CStr, c_char},
};

use aya::{
    Ebpf,
    maps::{Array, MapData},
    programs::UProbe,
};
use integration_common::strncmp::TestResult;

#[test]
fn bpf_strncmp() {
    let mut bpf = Ebpf::load(crate::STRNCMP).unwrap();

    {
        let prog: &mut UProbe = bpf
            .program_mut("test_bpf_strncmp")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();

        prog.attach("trigger_bpf_strncmp", "/proc/self/exe", None, None)
            .unwrap();
    }

    let array = Array::<_, TestResult>::try_from(bpf.map("RESULT").unwrap()).unwrap();

    assert_eq!(do_bpf_strncmp(&array, c"ff"), Ordering::Equal);

    // This is truncated in BPF; the buffer size is 3 including the null terminator.
    assert_eq!(do_bpf_strncmp(&array, c"fff"), Ordering::Equal);

    assert_eq!(do_bpf_strncmp(&array, c"aa"), Ordering::Less);
    assert_eq!(do_bpf_strncmp(&array, c"zz"), Ordering::Greater);
}

fn do_bpf_strncmp(array: &Array<&MapData, TestResult>, s1: &CStr) -> Ordering {
    trigger_bpf_strncmp(s1.as_ptr());
    let TestResult(ord) = array.get(&0, 0).unwrap();
    ord
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_bpf_strncmp(s1: *const c_char) {
    core::hint::black_box(s1);
}
