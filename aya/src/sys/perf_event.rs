use std::{
    ffi::{CString, OsStr, c_int},
    io, mem,
    os::fd::{BorrowedFd, FromRawFd as _},
};

use aya_obj::generated::{
    HW_BREAKPOINT_EMPTY, HW_BREAKPOINT_R, HW_BREAKPOINT_RW, HW_BREAKPOINT_W, HW_BREAKPOINT_X,
    PERF_FLAG_FD_CLOEXEC, perf_event_attr,
    perf_event_sample_format::PERF_SAMPLE_RAW,
    perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT,
    perf_type_id::{PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT},
};
use libc::pid_t;

use super::{PerfEventIoctlRequest, Syscall, syscall};
use crate::programs::perf_event::{BreakpointConfig, PerfBreakpointSize};

#[expect(clippy::too_many_arguments)]
pub(crate) fn perf_event_open(
    perf_type: u32,
    config: u64,
    pid: pid_t,
    cpu: c_int,
    sample_period: u64,
    sample_frequency: Option<u64>,
    inherit: bool,
    flags: u32,
    breakpoint: Option<BreakpointConfig>,
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    attr.config = config;
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = perf_type;
    attr.sample_type = PERF_SAMPLE_RAW as u64;
    attr.set_inherit(if inherit { 1 } else { 0 });

    if let Some(frequency) = sample_frequency {
        attr.set_freq(1);
        attr.__bindgen_anon_1.sample_freq = frequency;
    } else {
        attr.__bindgen_anon_1.sample_period = sample_period;
    }

    if let Some(bp) = breakpoint {
        let (type_, length, address) = match bp {
            BreakpointConfig::Empty { size, address } => (HW_BREAKPOINT_EMPTY, size, address),
            BreakpointConfig::Read { size, address } => (HW_BREAKPOINT_R, size, address),
            BreakpointConfig::Write { size, address } => (HW_BREAKPOINT_W, size, address),
            BreakpointConfig::ReadWrite { size, address } => (HW_BREAKPOINT_RW, size, address),
            BreakpointConfig::Execute { address } => (
                HW_BREAKPOINT_X,
                PerfBreakpointSize::from_primitive(std::mem::size_of::<libc::c_long>() as u64),
                address,
            ),
        };
        attr.bp_type = type_;
        attr.__bindgen_anon_3.bp_addr = address;
        attr.__bindgen_anon_4.bp_len = length.into_primitive();
        attr.set_precise_ip(2);
        attr.__bindgen_anon_2.wakeup_events = u32::from(true);
    } else {
        attr.__bindgen_anon_2.wakeup_events = u32::from(false);
    }

    perf_event_sys(attr, pid, cpu, flags)
}

pub(crate) fn perf_event_open_bpf(cpu: c_int) -> io::Result<crate::MockableFd> {
    perf_event_open(
        PERF_TYPE_SOFTWARE as u32,
        PERF_COUNT_SW_BPF_OUTPUT as u64,
        -1,
        cpu,
        1,
        None,
        true,
        PERF_FLAG_FD_CLOEXEC,
        None,
    )
}

pub(crate) fn perf_event_open_probe(
    ty: u32,
    ret_bit: Option<u32>,
    name: &OsStr,
    offset: u64,
    pid: Option<pid_t>,
) -> io::Result<crate::MockableFd> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    if let Some(ret_bit) = ret_bit {
        attr.config = 1 << ret_bit;
    }

    let c_name = CString::new(name.as_bytes()).unwrap();

    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = ty;
    attr.__bindgen_anon_3.config1 = c_name.as_ptr() as u64;
    attr.__bindgen_anon_4.config2 = offset;

    let cpu = if pid.is_some() { -1 } else { 0 };
    let pid = pid.unwrap_or(-1);

    perf_event_sys(attr, pid, cpu, PERF_FLAG_FD_CLOEXEC)
}

pub(crate) fn perf_event_open_trace_point(
    id: u32,
    pid: Option<pid_t>,
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = PERF_TYPE_TRACEPOINT as u32;
    attr.config = u64::from(id);

    let cpu = if pid.is_some() { -1 } else { 0 };
    let pid = pid.unwrap_or(-1);

    perf_event_sys(attr, pid, cpu, PERF_FLAG_FD_CLOEXEC)
}

pub(crate) fn perf_event_ioctl(
    fd: BorrowedFd<'_>,
    request: PerfEventIoctlRequest<'_>,
) -> io::Result<()> {
    syscall(Syscall::PerfEventIoctl { fd, request })
        .map(|code| {
            assert_eq!(code, 0);
        })
        .map_err(|(code, io_error)| {
            assert_eq!(code, -1);
            io_error
        })
}

fn perf_event_sys(
    attr: perf_event_attr,
    pid: pid_t,
    cpu: i32,
    flags: u32,
) -> io::Result<crate::MockableFd> {
    let fd = syscall(Syscall::PerfEventOpen {
        attr,
        pid,
        cpu,
        group: -1,
        flags,
    })
    .map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        io_error
    })?;

    let fd = fd.try_into().map_err(|std::num::TryFromIntError { .. }| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("perf_event_open: invalid fd returned: {fd}"),
        )
    })?;

    // SAFETY: perf_event_open returns a new file descriptor on success.
    unsafe { Ok(crate::MockableFd::from_raw_fd(fd)) }
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
