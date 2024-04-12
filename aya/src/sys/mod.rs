mod bpf;
mod netlink;
mod perf_event;

#[cfg(test)]
mod fake;

use std::{
    ffi::{c_int, c_long, c_void},
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd},
};

pub(crate) use bpf::*;
#[cfg(test)]
pub(crate) use fake::*;
use libc::{pid_t, SYS_bpf, SYS_perf_event_open};
pub(crate) use netlink::*;
#[doc(hidden)]
pub use netlink::{
    netlink_add_ip_addr, netlink_add_veth_pair, netlink_delete_link, netlink_set_link_down,
    netlink_set_link_up,
};
pub(crate) use perf_event::*;
use thiserror::Error;

use crate::generated::{bpf_attr, bpf_cmd, perf_event_attr};

pub(crate) type SysResult<T> = Result<T, (c_long, io::Error)>;

pub(crate) enum Syscall<'a> {
    Ebpf {
        cmd: bpf_cmd,
        attr: &'a mut bpf_attr,
    },
    PerfEventOpen {
        attr: perf_event_attr,
        pid: pid_t,
        cpu: i32,
        group: i32,
        flags: u32,
    },
    PerfEventIoctl {
        fd: BorrowedFd<'a>,
        request: c_int,
        arg: c_int,
    },
}

#[derive(Debug, Error)]
#[error("`{call}` failed")]
pub struct SyscallError {
    /// The name of the syscall which failed.
    pub(crate) call: &'static str,
    /// The [`io::Error`] returned by the syscall.
    #[source]
    pub(crate) io_error: io::Error,
}

impl std::fmt::Debug for Syscall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ebpf { cmd, attr: _ } => f
                .debug_struct("Syscall::Ebpf")
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

fn syscall(call: Syscall<'_>) -> SysResult<c_long> {
    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });

    #[cfg_attr(test, allow(unreachable_code))]
    match unsafe {
        match call {
            Syscall::Ebpf { cmd, attr } => {
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
                let int = libc::ioctl(fd.as_raw_fd(), request.try_into().unwrap(), arg);
                #[allow(trivial_numeric_casts)]
                let int = int as c_long;
                int
            }
        }
    } {
        ret @ 0.. => Ok(ret),
        ret => Err((ret, io::Error::last_os_error())),
    }
}

#[cfg_attr(test, allow(unused_variables))]
pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: BorrowedFd<'_>,
    offset: libc::off_t,
) -> *mut c_void {
    #[cfg(not(test))]
    return libc::mmap(addr, len, prot, flags, fd.as_raw_fd(), offset);

    #[cfg(test)]
    TEST_MMAP_RET.with(|ret| *ret.borrow())
}
