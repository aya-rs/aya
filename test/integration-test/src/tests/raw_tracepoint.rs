use aya::{Ebpf, maps::Array, programs::RawTracePoint};
use integration_common::raw_tracepoint::SysEnterEvent;

fn get_event(bpf: &mut Ebpf) -> SysEnterEvent {
    let map: Array<_, SysEnterEvent> = Array::try_from(bpf.map_mut("RESULT").unwrap()).unwrap();
    map.get(&0, 0).unwrap()
}

#[test_log::test]
fn raw_tracepoint() {
    let mut bpf = Ebpf::load(crate::RAW_TRACEPOINT).unwrap();

    // Check start condition.
    {
        let SysEnterEvent {
            common_type,
            common_flags,
            ..
        } = get_event(&mut bpf);
        assert_eq!(common_type, 0);
        assert_eq!(common_flags, 0);
    }

    // NB: we cannot fetch `map` just once above because both `Ebpf::map_mut` and
    // `Ebpf::program_mut` take &mut self, resulting in overlapping mutable borrows.
    let prog: &mut RawTracePoint = bpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sys_enter").unwrap();

    // Check that a syscall was traced.
    {
        let SysEnterEvent {
            common_type,
            common_flags,
            ..
        } = get_event(&mut bpf);
        assert_ne!(common_type, 0);
        assert_ne!(common_flags, 0);
    }
}
