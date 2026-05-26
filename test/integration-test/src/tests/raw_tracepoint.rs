use std::fs::{self, File, read};

use aya::{Ebpf, EbpfLoader, maps::Array, programs::RawTracePoint};
use integration_common::raw_tracepoint::{SysEnterEvent, TaskRenameEvent};
use scopeguard::defer;

fn get_sys_enter_event(bpf: &mut Ebpf) -> SysEnterEvent {
    let map: Array<_, SysEnterEvent> = Array::try_from(bpf.map_mut("RESULT").unwrap()).unwrap();
    map.get(&0, 0).unwrap()
}

fn get_task_rename_event(bpf: &mut Ebpf) -> TaskRenameEvent {
    let map: Array<_, TaskRenameEvent> =
        Array::try_from(bpf.map_mut("TASK_RENAME_RESULT").unwrap()).unwrap();
    map.get(&0, 0).unwrap()
}

#[test_log::test]
fn raw_tracepoint_sys_enter() {
    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::RAW_TRACEPOINT)
        .unwrap();

    let prog: &mut RawTracePoint = bpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sys_enter").unwrap();

    // Trigger a deterministic syscall after attaching the raw tracepoint.
    File::open("/dev/null").unwrap();

    let SysEnterEvent { regs_addr, .. } = get_sys_enter_event(&mut bpf);
    assert_ne!(regs_addr, 0);
}

#[test_log::test]
fn raw_tracepoint_task_rename() {
    let target_tgid = std::process::id();
    let mut bpf = EbpfLoader::new()
        .override_global("TARGET_TGID", &target_tgid, true)
        .load(crate::RAW_TRACEPOINT)
        .unwrap();

    let prog: &mut RawTracePoint = bpf.program_mut("task_rename").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("task_rename").unwrap();

    let original_comm = read("/proc/self/comm").unwrap();
    // Reading /proc/self/comm includes a trailing newline; don't restore it.
    let restore_comm = original_comm.strip_suffix(b"\n").unwrap_or(&original_comm);
    fs::write("/proc/self/comm", b"aya-raw-tp").unwrap();
    defer! {
        fs::write("/proc/self/comm", restore_comm).unwrap();
    }

    // Check that the task_rename event was traced.
    let TaskRenameEvent {
        task_addr,
        comm_addr,
    } = get_task_rename_event(&mut bpf);

    assert_ne!(task_addr, 0);
    assert_ne!(comm_addr, 0);
}
