use std::sync::{Arc, Condvar, Mutex};

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

    let pair_parent = Arc::new((Mutex::new(None), Condvar::new()));
    let pair_child = Arc::clone(&pair_parent);

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Wait for the child process to notify us about its PID.
        let (lock, cvar) = &*pair_parent;
        let mut child_pid = lock.lock().unwrap();
        while child_pid.is_none() {
            child_pid = cvar.wait(child_pid).unwrap();
        }

        // Check whether the child PID is present in the storage.
        let child_pid = child_pid.unwrap();
        let value = store.get(&child_pid, 0).unwrap();
        assert_eq!(value, 1);
    } else {
        // Notify the parent about the child PID.
        let (lock, cvar) = &*pair_child;
        let mut child_pid = lock.lock().unwrap();
        *child_pid = Some(pid as u32);
        cvar.notify_one();
    }
}
