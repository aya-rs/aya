mod btf;
pub(crate) mod feature_probe;
mod link;
mod map;
mod netlink;
mod object;
mod perf_event;
mod program;
mod utils;

#[cfg(test)]
mod fake;

use std::{
    ffi::{c_int, c_void},
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd},
};

use aya_obj::VerifierLog;
pub(crate) use btf::*;
#[cfg(test)]
pub(crate) use fake::*;
use libc::{pid_t, SYS_bpf, SYS_perf_event_open, ENOSPC};
pub(crate) use link::*;
pub(crate) use map::*;
#[doc(hidden)]
pub use netlink::netlink_set_link_up;
pub(crate) use netlink::*;
pub(crate) use object::*;
pub(crate) use perf_event::*;
pub(crate) use program::*;
use thiserror::Error;
pub(crate) use utils::*;

use crate::generated::{bpf_attr, bpf_cmd, perf_event_attr};

pub(crate) type SysResult<T> = Result<T, (i64, io::Error)>;

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
    pub call: &'static str,
    /// The [`io::Error`] returned by the syscall.
    #[source]
    pub io_error: io::Error,
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

fn syscall(call: Syscall<'_>) -> SysResult<i64> {
    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });

    #[cfg_attr(test, allow(unreachable_code))]
    {
        let ret = unsafe {
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
                    let ret = libc::ioctl(fd.as_raw_fd(), request.try_into().unwrap(), arg);
                    // `libc::ioctl` returns i32 on x86_64 while `libc::syscall` returns i64.
                    #[allow(clippy::useless_conversion)]
                    ret.into()
                }
            }
        };

        // `libc::syscall` returns i32 on armv7.
        #[allow(clippy::useless_conversion)]
        match ret.into() {
            ret @ 0.. => Ok(ret),
            ret => Err((ret, io::Error::last_os_error())),
        }
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

pub(crate) fn retry_with_verifier_logs<T>(
    max_retries: usize,
    f: impl Fn(&mut [u8]) -> SysResult<T>,
) -> (SysResult<T>, VerifierLog) {
    const MIN_LOG_BUF_SIZE: usize = 1024 * 10;
    const MAX_LOG_BUF_SIZE: usize = (u32::MAX >> 8) as usize;

    let mut log_buf = Vec::new();
    let mut retries = 0;
    loop {
        let ret = f(log_buf.as_mut_slice());
        if retries != max_retries {
            if let Err((_, io_error)) = &ret {
                if retries == 0 || io_error.raw_os_error() == Some(ENOSPC) {
                    let len = (log_buf.capacity() * 10).clamp(MIN_LOG_BUF_SIZE, MAX_LOG_BUF_SIZE);
                    log_buf.resize(len, 0);
                    if let Some(first) = log_buf.first_mut() {
                        *first = 0;
                    }
                    retries += 1;
                    continue;
                }
            }
        }
        if let Some(pos) = log_buf.iter().position(|b| *b == 0) {
            log_buf.truncate(pos);
        }
        let log_buf = String::from_utf8(log_buf).unwrap();

        break (ret, VerifierLog::new(log_buf));
    }
}
