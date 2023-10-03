use aya::{maps::Array, programs::RawTracePoint, Ebpf};
use integration_common::raw_tracepoint::SysEnterEvent;

#[test]
fn raw_tracepoint() {
    let mut bpf = Ebpf::load(crate::RAW_TRACEPOINT).unwrap();
    let prog: &mut RawTracePoint = bpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sys_enter").unwrap();

    let map: Array<_, SysEnterEvent> = Array::try_from(bpf.map_mut("RESULT").unwrap()).unwrap();
    let SysEnterEvent {
        common_type,
        common_flags,
        ..
    } = map.get(&0, 0).unwrap();
    assert_ne!(common_type, 0);
    assert_ne!(common_flags, 0);
}
