use aya::{
    Btf, Ebpf,
    programs::{BtfTracePoint, TracePoint, Xdp},
};
use test_log::test;

#[test]
fn test_ksym_btf_tracepoint() {
    let mut ebpf = Ebpf::load(crate::KSYMS).unwrap();
    let prog: &mut BtfTracePoint = ebpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    prog.load("sys_enter", &btf).unwrap();
    prog.attach().unwrap();
}

// #[test]
// fn test_ksym_tracepoint() {
//     let mut ebpf = Ebpf::load(crate::KSYMS_RS).unwrap();
//     let prog: &mut TracePoint = ebpf.program_mut("sys_enter").unwrap().try_into().unwrap();
//     prog.load().unwrap();
//     prog.attach("sched", "sched_switch").unwrap();
// }
