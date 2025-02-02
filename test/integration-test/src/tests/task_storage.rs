use std::{process::Command, thread::sleep, time::Duration};

use aya::{maps::TaskStorage, programs::FEntry, Btf, Ebpf};
use test_log::test;

#[test]
fn test_task_storage_get() {
    let mut ebpf = Ebpf::load(crate::TASK_STORAGE).unwrap();

    let prog: &mut FEntry = ebpf.program_mut("task_alloc").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    prog.load("security_task_alloc", &btf).unwrap();
    prog.attach().unwrap();

    let store: TaskStorage<_, u32> =
        TaskStorage::try_from(ebpf.map_mut("task_storage").unwrap()).unwrap();

    let mut child = Command::new("sleep").arg("1").spawn().unwrap();
    let pid = child.id();

    sleep(Duration::from_millis(1));

    let value = store.get(&pid, 0).unwrap();
    assert_eq!(value, 1);

    child.kill().unwrap();
    child.wait().unwrap();
}
