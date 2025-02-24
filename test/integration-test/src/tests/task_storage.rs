use std::{thread::sleep, time::Duration};

use aya::{maps::TaskStorage, programs::BtfTracePoint, Btf, Ebpf};
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

    // Trigger the eBPF program by issuing a syscall (`gettid`).
    //
    // Why `gettid` and not `getpid`?
    //
    // `gettid` returns the PID of the current task, regardless of whether that
    // task is a thread (lightweight process with shared resources) or a
    // regular process.
    //
    // `getpid` always returns the PID of a regular process. Called in a
    // thread, it returns the PID of the parent task, which is the original
    // "owner" of the shared resources.
    //
    // The "process vs thread" distinction is made in these syscalls mostly
    // because user-space applications are used to this concept. Such
    // distinction isn't used much inside the kernel.
    //
    // `bpf_get_current_task_btf()` doesn't make such distinction either. If
    // your eBPF program is triggered by a thread, `bpf_get_current_task_btf()`
    // returns a `struct task_struct*` representing a thread. `task->pid` of
    // that task refers to a thread. Therefore, we need to use a TID to
    // retrieve the task storage entry from the user-space.
    let tid = unsafe { libc::gettid() } as u32;

    sleep(Duration::from_millis(10));

    let value = task_storage.get(&tid, 0).unwrap();
    assert_eq!(value, 1);
}
