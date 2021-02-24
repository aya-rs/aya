use std::{ffi::CString, mem};

use libc::{c_int, c_ulong, pid_t};

use crate::generated::{
    perf_event_attr,
    perf_event_sample_format::PERF_SAMPLE_RAW,
    perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT,
    perf_type_id::{PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT},
    PERF_FLAG_FD_CLOEXEC,
};

use super::{syscall, SysResult, Syscall};

pub(crate) fn perf_event_open(cpu: c_int) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    attr.config = PERF_COUNT_SW_BPF_OUTPUT as u64;
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_SOFTWARE as u32;
    attr.sample_type = PERF_SAMPLE_RAW as u64;
    attr.__bindgen_anon_1.sample_period = 1;
    attr.__bindgen_anon_2.wakeup_events = 1;

    syscall(Syscall::PerfEventOpen {
        attr,
        pid: -1,
        cpu,
        group: -1,
        flags: PERF_FLAG_FD_CLOEXEC,
    })
}

pub(crate) fn perf_event_open_probe(
    ty: u32,
    ret_bit: Option<u32>,
    name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    if let Some(ret_bit) = ret_bit {
        attr.config = 1 << ret_bit;
    }

    let c_name = CString::new(name).unwrap();

    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = ty;
    attr.__bindgen_anon_3.config1 = c_name.as_ptr() as u64;
    attr.__bindgen_anon_4.config2 = offset;

    let cpu = if pid.is_some() { -1 } else { 0 };
    let pid = pid.unwrap_or(-1);

    syscall(Syscall::PerfEventOpen {
        attr,
        pid,
        cpu,
        group: -1,
        flags: PERF_FLAG_FD_CLOEXEC,
    })
}

pub(crate) fn perf_event_open_trace_point(id: u32) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_TRACEPOINT as u32;
    attr.config = id as u64;

    syscall(Syscall::PerfEventOpen {
        attr,
        pid: -1,
        cpu: 0,
        group: -1,
        flags: PERF_FLAG_FD_CLOEXEC,
    })
}

pub(crate) fn perf_event_ioctl(fd: c_int, request: c_ulong, arg: c_int) -> SysResult {
    let call = Syscall::PerfEventIoctl { fd, request, arg };
    #[cfg(not(test))]
    return syscall(call);

    #[cfg(test)]
    return crate::sys::TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });
}

/*
impl TryFrom<u32> for perf_event_type {
    PERF_RECORD_MMAP = 1,
    PERF_RECORD_LOST = 2,
    PERF_RECORD_COMM = 3,
    PERF_RECORD_EXIT = 4,
    PERF_RECORD_THROTTLE = 5,
    PERF_RECORD_UNTHROTTLE = 6,
    PERF_RECORD_FORK = 7,
    PERF_RECORD_READ = 8,
    PERF_RECORD_SAMPLE = 9,
    PERF_RECORD_MMAP2 = 10,
    PERF_RECORD_AUX = 11,
    PERF_RECORD_ITRACE_START = 12,
    PERF_RECORD_LOST_SAMPLES = 13,
    PERF_RECORD_SWITCH = 14,
    PERF_RECORD_SWITCH_CPU_WIDE = 15,
    PERF_RECORD_NAMESPACES = 16,
    PERF_RECORD_KSYMBOL = 17,
    PERF_RECORD_BPF_EVENT = 18,
    PERF_RECORD_CGROUP = 19,
    PERF_RECORD_MAX

    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        todo!()
    }
}
*/
