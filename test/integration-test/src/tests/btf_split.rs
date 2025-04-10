//! Test to make sure loading split BTF (kernel module BTF) works properly.

use aya::{maps::Array, programs::UProbe, util::KernelVersion, Btf, EbpfLoader, Endianness};
use test_case::test_case;

#[test]
fn rebase_tests() {
    // First, check that we have ip_tables in the split btf.
    if !std::fs::exists("/sys/kernel/btf/ip_tables") {
        eprintln!("skipping test on kernel, as ip_tables is not loaded as an external kernel module.");
        return;
    }
    let mut bpf = EbpfLoader::new()
        .load(crate::SPLIT_BPF)
        .unwrap();
    let program: &mut UProbe = bpf.program_mut(program).unwrap().try_into().unwrap();
    program.load().unwrap();
    program
        .attach(
            Some("trigger_btf_split_program"),
            0,
            "/proc/self/exe",
            None,
        )
        .unwrap();

    trigger_btf_split_program();

    let output_map: Array<_, u64> = bpf.take_map("output_map").unwrap().try_into().unwrap();
    let key = 0;
    assert_eq!(output_map.get(&key, 0).unwrap(), 1)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_btf_split_program() {
    core::hint::black_box(trigger_btf_split_program);
}
