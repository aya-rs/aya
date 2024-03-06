use aya::{maps::Array, programs::RawTracePoint, Bpf};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysEnterEvent {
    pub common_type: u16,
    pub common_flags: u8,
    _padding: u8,
}

unsafe impl aya::Pod for SysEnterEvent {}

#[test]
fn raw_tracepoint() {
    let mut bpf = Bpf::load(crate::RAW_TRACEPOINT).unwrap();
    let prog: &mut RawTracePoint = bpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sys_enter").unwrap();

    let map: Array<_, SysEnterEvent> = Array::try_from(bpf.map_mut("RESULT").unwrap()).unwrap();
    let result = map.get(&0, 0).unwrap();

    assert_ne!(result.common_type, 0);
    assert_ne!(result.common_flags, 0);
}
