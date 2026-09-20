use std::{
    ffi::{CString, OsStr, c_long, c_uint},
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _},
};

use aya_obj::generated::{
    HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_LEN_2, HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_LEN_8,
    HW_BREAKPOINT_X, PERF_FLAG_FD_CLOEXEC, perf_event_attr,
    perf_event_read_format::{
        PERF_FORMAT_GROUP, PERF_FORMAT_TOTAL_TIME_ENABLED, PERF_FORMAT_TOTAL_TIME_RUNNING,
    },
    perf_event_sample_format::PERF_SAMPLE_RAW,
    perf_type_id::{
        PERF_TYPE_BREAKPOINT, PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE, PERF_TYPE_RAW,
        PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
    },
};
use libc::pid_t;

use super::{PerfEventIoctlRequest, Syscall, syscall};
use crate::programs::perf_event::{
    BreakpointConfig, PerfEventConfig, PerfEventScope, SamplePolicy, WakeupPolicy,
    perf_type_id_to_u32,
};

pub(crate) fn perf_event_open(
    config: PerfEventConfig,
    scope: PerfEventScope,
    sample_policy: SamplePolicy,
    wakeup_policy: WakeupPolicy,
    inherit: bool,
    flags: u32,
) -> io::Result<crate::MockableFd> {
    let mut attr = perf_event_attr(config);
    attr.sample_type = PERF_SAMPLE_RAW as u64;
    attr.set_inherit(u64::from(inherit));

    match sample_policy {
        SamplePolicy::Period(period) => {
            attr.__bindgen_anon_1.sample_period = period;
        }
        SamplePolicy::Frequency(frequency) => {
            attr.set_freq(1);
            attr.__bindgen_anon_1.sample_freq = frequency;
        }
    }

    match wakeup_policy {
        WakeupPolicy::Events(events) => {
            attr.__bindgen_anon_2.wakeup_events = events;
        }
        WakeupPolicy::Watermark(watermark) => {
            attr.set_watermark(1);
            attr.__bindgen_anon_2.wakeup_watermark = watermark;
        }
    }

    let (pid, cpu) = perf_event_scope(scope);
    perf_event_sys(attr, pid, cpu, None, flags)
}

pub(crate) fn perf_event_open_group_member(
    config: PerfEventConfig,
    scope: PerfEventScope,
    group: Option<BorrowedFd<'_>>,
) -> io::Result<crate::MockableFd> {
    let mut attr = perf_event_attr(config);
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED as u64
        | PERF_FORMAT_TOTAL_TIME_RUNNING as u64
        | PERF_FORMAT_GROUP as u64;
    attr.set_disabled(u64::from(group.is_none()));

    let (pid, cpu) = perf_event_scope(scope);
    perf_event_sys(attr, pid, cpu, group, PERF_FLAG_FD_CLOEXEC)
}

fn perf_event_attr(config: PerfEventConfig) -> perf_event_attr {
    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };
    let (perf_type, config) = match config {
        PerfEventConfig::Pmu { pmu_type, config } => (pmu_type, config),
        PerfEventConfig::Hardware(hw_event) => (
            perf_type_id_to_u32(PERF_TYPE_HARDWARE),
            u64::from(hw_event.into_primitive()),
        ),
        PerfEventConfig::Software(sw_event) => (
            perf_type_id_to_u32(PERF_TYPE_SOFTWARE),
            u64::from(sw_event.into_primitive()),
        ),
        PerfEventConfig::TracePoint { event_id } => {
            (perf_type_id_to_u32(PERF_TYPE_TRACEPOINT), event_id)
        }
        PerfEventConfig::HwCache {
            event,
            operation,
            result,
        } => (
            perf_type_id_to_u32(PERF_TYPE_HW_CACHE),
            u64::from(event.into_primitive())
                | (u64::from(operation.into_primitive()) << 8)
                | (u64::from(result.into_primitive()) << 16),
        ),
        PerfEventConfig::Raw { event_id } => (perf_type_id_to_u32(PERF_TYPE_RAW), event_id),
        PerfEventConfig::Breakpoint(breakpoint) => {
            let (type_, address, length) = match breakpoint {
                BreakpointConfig::Data {
                    r#type,
                    address,
                    length,
                } => (
                    r#type.into_primitive(),
                    address,
                    u64::from(length.into_primitive()),
                ),
                BreakpointConfig::Instruction { address } => {
                    #[expect(
                        clippy::panic,
                        reason = "unsupported c_long size indicates an unsupported platform"
                    )]
                    const fn length(size: usize) -> c_uint {
                        match size {
                            1 => HW_BREAKPOINT_LEN_1,
                            2 => HW_BREAKPOINT_LEN_2,
                            4 => HW_BREAKPOINT_LEN_4,
                            8 => HW_BREAKPOINT_LEN_8,
                            // NB: cannot emit the value because:
                            //
                            // error[E0015]: cannot call non-const formatting macro in constant functions
                            _ => panic!("invalid hardware breakpoint size"),
                        }
                    }
                    const LENGTH: c_uint = length(size_of::<c_long>());
                    (HW_BREAKPOINT_X, address, u64::from(LENGTH))
                }
            };

            attr.bp_type = type_;
            attr.__bindgen_anon_3.bp_addr = address;
            attr.__bindgen_anon_4.bp_len = length;
            attr.set_precise_ip(2);

            (perf_type_id_to_u32(PERF_TYPE_BREAKPOINT), 0)
        }
    };

    attr.config = config;
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = perf_type;
    attr
}

fn perf_event_scope(scope: PerfEventScope) -> (pid_t, i32) {
    match scope {
        PerfEventScope::CallingProcess { cpu } => (0, cpu.map_or(-1, |cpu| cpu as i32)),
        PerfEventScope::OneProcess { pid, cpu } => (pid as i32, cpu.map_or(-1, |cpu| cpu as i32)),
        PerfEventScope::AllProcessesOneCpu { cpu } => (-1, cpu as i32),
    }
}

pub(crate) fn perf_event_open_probe(
    ty: u32,
    ret_bit: Option<u32>,
    name: &OsStr,
    offset: u64,
    pid: Option<u32>,
) -> io::Result<crate::MockableFd> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

    if let Some(ret_bit) = ret_bit {
        attr.config = 1 << ret_bit;
    }

    let c_name = CString::new(name.as_bytes())?;

    attr.size = size_of::<perf_event_attr>() as u32;
    attr.type_ = ty;
    attr.__bindgen_anon_3.config1 = c_name.as_ptr() as u64;
    attr.__bindgen_anon_4.config2 = offset;

    let (pid, cpu) = match pid {
        Some(pid) => (pid as i32, -1),
        None => (-1, 0),
    };

    perf_event_sys(attr, pid, cpu, None, PERF_FLAG_FD_CLOEXEC)
}

pub(crate) fn perf_event_open_trace_point(
    event_id: u64,
    pid: Option<u32>,
) -> io::Result<crate::MockableFd> {
    let scope = match pid {
        Some(pid) => PerfEventScope::OneProcess { pid, cpu: None },
        None => PerfEventScope::AllProcessesOneCpu { cpu: 0 },
    };
    perf_event_open(
        PerfEventConfig::TracePoint { event_id },
        scope,
        SamplePolicy::Period(0),
        WakeupPolicy::Events(1),
        false,
        PERF_FLAG_FD_CLOEXEC,
    )
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

pub(crate) fn perf_event_read(fd: BorrowedFd<'_>, values: &mut [u64]) -> io::Result<()> {
    let len = size_of_val(values);
    let read = loop {
        match syscall(Syscall::PerfEventRead { fd, values }) {
            Ok(read) => break read,
            Err((_, io_error)) if io_error.kind() == io::ErrorKind::Interrupted => {}
            Err((_, io_error)) => return Err(io_error),
        }
    };
    let read = usize::try_from(read).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("perf event read returned an invalid byte count: {error}"),
        )
    })?;
    if read != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("perf event read returned {read} bytes, expected {len}"),
        ));
    }
    Ok(())
}

fn perf_event_sys(
    attr: perf_event_attr,
    pid: pid_t,
    cpu: i32,
    group: Option<BorrowedFd<'_>>,
    flags: u32,
) -> io::Result<crate::MockableFd> {
    let group = group.map_or(-1, |fd| fd.as_raw_fd());
    let fd = syscall(Syscall::PerfEventOpen {
        attr,
        pid,
        cpu,
        group,
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
