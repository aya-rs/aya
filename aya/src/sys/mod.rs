mod bpf;
mod netlink;
mod perf_event;

#[cfg(test)]
mod fake;

use std::{io, mem};

use libc::{c_int, c_long, pid_t, SYS_bpf, SYS_perf_event_open};

pub(crate) use bpf::*;
#[cfg(test)]
pub(crate) use fake::*;
#[doc(hidden)]
pub use netlink::netlink_set_link_up;
pub(crate) use netlink::*;
pub(crate) use perf_event::*;

use crate::generated::{bpf_attr, bpf_cmd, perf_event_attr};

pub(crate) type SysResult<T> = Result<T, (c_long, io::Error)>;

pub(crate) enum Syscall<'a> {
    Bpf {
        cmd: bpf_cmd,
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
        request: c_int,
        arg: c_int,
    },
}

impl std::fmt::Debug for Syscall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bpf { cmd, attr: _ } => f
                .debug_struct("Syscall::Bpf")
                .field("cmd", cmd)
                .field("attr", &format_args!("_"))
                .finish(),
            Self::PerfEventOpen {
                attr: _,
                pid,
                cpu,
                group,
                flags,
            } => f
                .debug_struct("Syscall::PerfEventOpen")
                .field("attr", &format_args!("_"))
                .field("pid", pid)
                .field("cpu", cpu)
                .field("group", group)
                .field("flags", flags)
                .finish(),
            Self::PerfEventIoctl { fd, request, arg } => f
                .debug_struct("Syscall::PerfEventIoctl")
                .field("fd", fd)
                .field("request", request)
                .field("arg", arg)
                .finish(),
        }
    }
}

fn syscall(call: Syscall) -> SysResult<c_long> {
    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });

    #[cfg_attr(test, allow(unreachable_code))]
    match unsafe {
        match call {
            Syscall::Bpf { cmd, attr } => {
                libc::syscall(SYS_bpf, cmd, attr, mem::size_of::<bpf_attr>())
            }
            Syscall::PerfEventOpen {
                attr,
                pid,
                cpu,
                group,
                flags,
            } => libc::syscall(SYS_perf_event_open, &attr, pid, cpu, group, flags),
            Syscall::PerfEventIoctl { fd, request, arg } => {
                libc::ioctl(fd, request.try_into().unwrap(), arg) as libc::c_long
            }
        }
    } {
        ret @ 0.. => Ok(ret),
        ret => Err((ret, io::Error::last_os_error())),
    }
}
