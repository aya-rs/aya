//! A collection of system calls for performing eBPF related operations.

mod bpf;
mod netlink;
mod perf_event;

#[cfg(test)]
mod fake;

use std::{
    ffi::{c_int, c_long, c_void},
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd},
};

use aya_obj::generated::{bpf_attr, bpf_cmd, perf_event_attr};
pub(crate) use bpf::*;
#[cfg(test)]
pub(crate) use fake::*;
use libc::{pid_t, SYS_bpf, SYS_ioctl, SYS_perf_event_open};
#[doc(hidden)]
pub use netlink::netlink_set_link_up;
pub(crate) use netlink::*;
pub(crate) use perf_event::*;
use thiserror::Error;

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

/// A system call error.
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

fn syscall(call: Syscall<'_>) -> SysResult<c_long> {
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
                    libc::syscall(SYS_ioctl, fd.as_raw_fd(), request, arg)
                }
            }
        };

        match ret {
            0.. => Ok(ret),
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

/// The type of eBPF statistic to enable.
#[non_exhaustive]
#[doc(alias = "bpf_stats_type")]
#[derive(Copy, Clone, Debug)]
pub enum Stats {
    /// Tracks [`run_time`](crate::programs::ProgramInfo::run_time) and
    /// [`run_count`](crate::programs::ProgramInfo::run_count) fields.
    #[doc(alias = "BPF_STATS_RUN_TIME")]
    RunTime,
}

impl From<Stats> for aya_obj::generated::bpf_stats_type {
    fn from(value: Stats) -> Self {
        use aya_obj::generated::bpf_stats_type::*;

        match value {
            Stats::RunTime => BPF_STATS_RUN_TIME,
        }
    }
}

/// Enable global statistics tracking for eBPF programs and returns a
/// [file descriptor](`OwnedFd`) handler.
///
/// Statistics tracking is disabled when the [file descriptor](`OwnedFd`) is
/// dropped (either automatically when the variable goes out of scope or
/// manually through [`Drop`]).
///
/// Usage:
/// 1. Obtain fd from [`enable_stats`] and bind it to a variable.
/// 2. Record the statistic of interest.
/// 3. Wait for a recorded period of time.
/// 4. Record the statistic of interest again, and calculate the difference.
/// 5. Close/release fd automatically or manually.
///
/// Introduced in kernel v5.8.
///
/// # Examples
///
/// ```no_run
/// # use aya::sys::{SyscallError};
/// use aya::sys::{enable_stats, Stats};
///
/// let _fd = enable_stats(Stats::RunTime)?;
/// # Ok::<(), SyscallError>(())
/// ```
#[doc(alias = "BPF_ENABLE_STATS")]
pub fn enable_stats(stats_type: Stats) -> Result<OwnedFd, SyscallError> {
    bpf_enable_stats(stats_type.into()).map(|fd| fd.into_inner())
}
