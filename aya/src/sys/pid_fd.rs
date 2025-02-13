use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use libc::pid_t;

use crate::{
    sys::{SysResult, Syscall},
    MockableFd,
};

/// A file descriptor of a process.
///
/// A similar type is provided by the Rust standard library as
/// [`std::os::linux::process`] as a nigtly-only experimental API. We are
/// planning to migrate to it once it stabilizes.
pub(crate) struct PidFd(MockableFd);

impl PidFd {
    pub(crate) fn open(pid: u32, flags: u32) -> SysResult<Self> {
        let pid_fd = pidfd_open(pid, flags)? as RawFd;
        let pid_fd = unsafe { MockableFd::from_raw_fd(pid_fd) };
        Ok(Self(pid_fd))
    }
}

impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

fn pidfd_open(pid: u32, flags: u32) -> SysResult<i64> {
    let call = Syscall::PidfdOpen {
        pid: pid as pid_t,
        flags,
    };
    #[cfg(not(test))]
    return crate::sys::syscall(call);
    #[cfg(test)]
    return crate::sys::TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });
}
