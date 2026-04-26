use std::{cell::RefCell, ffi::c_void, io, ptr};

use super::{SysResult, Syscall};

type SyscallFn = dyn for<'a> Fn(Syscall<'a>) -> SysResult;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SYSCALL: RefCell<Box<SyscallFn>> = RefCell::new(Box::new(test_syscall));
    pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = const { RefCell::new(ptr::null_mut()) };
}

#[cfg(test)]
fn test_syscall(_call: Syscall<'_>) -> SysResult {
    Err((-1, io::Error::from_raw_os_error(libc::EINVAL)))
}

#[cfg(test)]
pub(crate) fn override_syscall(call: impl for<'a> Fn(Syscall<'a>) -> SysResult + 'static) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = Box::new(call));
}
