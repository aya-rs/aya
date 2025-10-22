use aya::{Btf, Ebpf, maps::Array, programs::BtfTracePoint};
use test_log::test;

#[test]
fn test_ksyms_c() {
    let mut ebpf = Ebpf::load(crate::KSYMS).unwrap();

    let prog: &mut BtfTracePoint = ebpf.program_mut("sys_enter").unwrap().try_into().unwrap();

    let btf = Btf::from_sys_fs().unwrap();
    prog.load("sys_enter", &btf).unwrap();
    prog.attach().unwrap();

    // Trigger the program by doing a syscall
    let _ = std::fs::metadata("/");

    // Read results from the output map
    let output: Array<_, u64> = Array::try_from(ebpf.map("output_map").unwrap()).unwrap();

    // Key 0: init_task address (typeless ksym) - should be non-zero
    let init_task_addr = output.get(&0, 0).unwrap();
    assert!(
        init_task_addr > 0,
        "init_task address should be non-zero, got {}",
        init_task_addr
    );

    // Key 1: kfunc availability (0 = not available, 1 = available)
    // We don't fail if kfunc isn't available - just log it
    let kfunc_available = output.get(&1, 0).unwrap();
    eprintln!(
        "ksyms test: init_task={:#x}, kfunc available={}",
        init_task_addr,
        kfunc_available == 1
    );
}
