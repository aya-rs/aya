use aya::{Btf, Ebpf, programs::BtfTracePoint};
use test_log::test;

#[test]
fn test_ksym() {
    let env = env!("OUT_DIR");
    println!("out dir {}", env);
    let mut ebpf = Ebpf::load(crate::KSYMS).unwrap();

    let prog: &mut BtfTracePoint = ebpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    prog.load("sys_enter", &btf).unwrap();
    prog.attach().unwrap();
}
