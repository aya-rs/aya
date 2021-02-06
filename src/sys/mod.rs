mod bpf;
mod perf_event;

#[cfg(test)]
mod fake;

use std::io;

use libc::{c_int, c_long, c_ulong, pid_t};

pub(crate) use bpf::*;
#[cfg(test)]
pub(crate) use fake::*;
pub(crate) use perf_event::*;

use crate::generated::{bpf_attr, bpf_cmd, perf_event_attr};

pub(crate) type SysResult = Result<c_long, (c_long, io::Error)>;

#[cfg_attr(test, allow(dead_code))]
pub(crate) enum Syscall<'a> {
    Bpf {
        cmd: bpf_cmd::Type,
        attr: &'a bpf_attr,
    },
    PerfEventOpen {
        attr: perf_event_attr,
        pid: pid_t,
        cpu: i32,
        group: i32,
        flags: u32,
    },
    PerfEventIoctl {
        fd: c_int,
        request: c_ulong,
        arg: c_int,
    },
}

fn syscall(call: Syscall) -> SysResult {
    #[cfg(not(test))]
    return unsafe { syscall_impl(call) };

    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });
}

#[cfg(not(test))]
unsafe fn syscall_impl(call: Syscall) -> SysResult {
    use libc::{SYS_bpf, SYS_perf_event_open};
    use std::mem;

    use Syscall::*;
    let ret = match call {
        Bpf { cmd, attr } => libc::syscall(SYS_bpf, cmd, attr, mem::size_of::<bpf_attr>()),
        PerfEventOpen {
            attr,
            pid,
            cpu,
            group,
            flags,
        } => libc::syscall(SYS_perf_event_open, &attr, pid, cpu, group, flags),
        PerfEventIoctl { fd, request, arg } => libc::ioctl(fd, request, arg) as i64,
    };

    if ret < 0 {
        return Err((ret, io::Error::last_os_error()));
    }

    Ok(ret)
}
