use crate::sys::{SysResult, Syscall};
use libc::pid_t;
use std::os::fd::{AsRawFd, RawFd};
/// A file descriptor of a process.
pub(crate) struct PidFd(RawFd);
impl PidFd {
    pub(crate) fn open(pid: u32, flags: u32) -> SysResult<Self> {
        let pid_fd = pidfd_open(pid, flags)?;
        Ok(Self(pid_fd as i32))
    }
}
impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl Drop for PidFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
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
