use std::{cell::RefCell, ffi::c_void, io, ptr};

use super::{SysResult, Syscall};

type SyscallFn = unsafe fn(Syscall<'_>) -> SysResult<i64>;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SYSCALL: RefCell<SyscallFn> = RefCell::new(test_syscall);
    pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = const { RefCell::new(ptr::null_mut()) };
}

#[cfg(test)]
unsafe fn test_syscall(call: Syscall<'_>) -> SysResult<i64> {
    use crate::errors::SysError;

    Err((
        -1,
        SysError::Syscall {
            call: format!("{:?}", call),
            io_error: io::Error::from_raw_os_error(libc::EINVAL),
        },
    ))
}

#[cfg(test)]
pub(crate) fn override_syscall(call: unsafe fn(Syscall<'_>) -> SysResult<i64>) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = call);
}
