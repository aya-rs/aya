use std::{cell::RefCell, io, ptr};

use libc::c_void;

use super::{SysResult, Syscall};

type SyscallFn = unsafe fn(Syscall) -> SysResult;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SYSCALL: RefCell<SyscallFn> = RefCell::new(test_syscall);
    pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = RefCell::new(ptr::null_mut());
}

#[cfg(test)]
unsafe fn test_syscall(_call: Syscall) -> SysResult {
    Err((-1, io::Error::from_raw_os_error(libc::EINVAL)))
}

#[cfg(test)]
pub(crate) fn override_syscall(call: unsafe fn(Syscall) -> SysResult) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = call);
}
