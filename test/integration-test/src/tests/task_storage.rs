use std::{thread::sleep, time::Duration};

use aya::{Btf, Ebpf, maps::TaskStorage, programs::BtfTracePoint};
use test_log::test;

#[test]
fn test_task_storage_get() {
    let mut ebpf = Ebpf::load(crate::TASK_STORAGE).unwrap();

    let prog: &mut BtfTracePoint = ebpf.program_mut("sys_enter").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    prog.load("sys_enter", &btf).unwrap();
    prog.attach().unwrap();

    let task_storage: TaskStorage<_, u32> =
        TaskStorage::try_from(ebpf.map_mut("task_storage").unwrap()).unwrap();

    // Trigger the eBPF program by issuing a syscall (`getpid`).
    let pid = unsafe { libc::getpid() } as u32;

    sleep(Duration::from_millis(10));

    let value = task_storage.get(&pid, 0).unwrap();
    assert_eq!(value, 1);
}
