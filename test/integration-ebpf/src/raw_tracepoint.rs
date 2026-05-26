#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    EbpfContext as _, Global,
    macros::{map, raw_tracepoint},
    maps::Array,
    programs::RawTracePointContext,
};
#[cfg(not(test))]
extern crate ebpf_panic;
use integration_common::raw_tracepoint::{SysEnterEvent, TaskRenameEvent};

#[map]
static RESULT: Array<SysEnterEvent> = Array::with_max_entries(1, 0);

#[map]
static TASK_RENAME_RESULT: Array<TaskRenameEvent> = Array::with_max_entries(1, 0);

#[unsafe(no_mangle)]
static TARGET_TGID: Global<u32> = Global::new(0);

#[raw_tracepoint(tracepoint = "sys_enter")]
fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let target_tgid = TARGET_TGID.load();
    if ctx.tgid() != target_tgid {
        return 0;
    }

    // Raw sys_enter args are `struct pt_regs *regs, long id`.
    // https://github.com/torvalds/linux/blob/v6.15/include/trace/events/syscalls.h#L18-L22
    let regs_addr: u64 = ctx.arg(0);
    let syscall_id: i64 = ctx.arg(1);

    if let Some(ptr) = RESULT.get_ptr_mut(0) {
        unsafe {
            if (*ptr).regs_addr != 0 {
                return 0;
            }
            (*ptr).regs_addr = regs_addr;
            (*ptr).syscall_id = syscall_id;
        }
    }

    0
}

#[raw_tracepoint(tracepoint = "task_rename")]
fn task_rename(ctx: RawTracePointContext) -> i32 {
    let target_tgid = TARGET_TGID.load();
    if ctx.tgid() != target_tgid {
        return 0;
    }

    // Raw task_rename args are `struct task_struct *task, const char *comm`.
    // https://github.com/torvalds/linux/blob/v6.15/include/trace/events/task.h#L34-L38
    let task_addr: u64 = ctx.arg(0);
    let comm_addr: u64 = ctx.arg(1);

    if let Some(ptr) = TASK_RENAME_RESULT.get_ptr_mut(0) {
        unsafe {
            if (*ptr).task_addr != 0 {
                return 0;
            }
            (*ptr).task_addr = task_addr;
            (*ptr).comm_addr = comm_addr;
        }
    }

    0
}
