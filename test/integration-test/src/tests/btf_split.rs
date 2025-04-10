//! Test to make sure loading split BTF (kernel module BTF) works properly.

use aya::{maps::Array, programs::UProbe, EbpfLoader};

#[test]
fn rebase_tests() {
    // First, check that we have ip_tables in the split btf.
    if !matches!(std::fs::exists("/sys/kernel/btf/ip_tables"), Ok(true)) {
        eprintln!("skipping test on kernel, as ip_tables is not loaded as an external kernel module.");
        return;
    }
    let mut bpf = EbpfLoader::new()
        .load(crate::SPLIT_BPF)
        .unwrap();
    let program: &mut UProbe = bpf.program_mut("check_can_access_module").unwrap().try_into().unwrap();
    program.load().unwrap();
    program
        .attach(
            "trigger_btf_split_program",
            "/proc/self/exe",
            None,
            None,
        )
        .unwrap();

    trigger_btf_split_program();

    let output_map: Array<_, u64> = bpf.take_map("output_map").unwrap().try_into().unwrap();
    let key = 0;
    assert_eq!(output_map.get(&key, 0).unwrap(), 1)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_btf_split_program() {
    core::hint::black_box(trigger_btf_split_program);
}
