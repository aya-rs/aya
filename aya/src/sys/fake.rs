use std::{cell::RefCell, ffi::c_void, io, ptr};

use libc::{c_int, off_t};

use super::{SysResult, Syscall};

type SyscallFn = unsafe fn(Syscall<'_>) -> SysResult;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SYSCALL: RefCell<SyscallFn> = RefCell::new(test_syscall);
    pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = const { RefCell::new(ptr::null_mut()) };
    pub(crate) static TEST_MMAP_CALL: RefCell<Option<MmapCall>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MmapCall {
    pub(crate) address: *mut c_void,
    pub(crate) length: usize,
    pub(crate) protection: c_int,
    pub(crate) flags: c_int,
    pub(crate) fd: i32,
    pub(crate) offset: off_t,
}

#[cfg(test)]
unsafe fn test_syscall(_call: Syscall<'_>) -> SysResult {
    Err((-1, io::Error::from_raw_os_error(libc::EINVAL)))
}

#[cfg(test)]
pub(crate) fn override_syscall(call: unsafe fn(Syscall<'_>) -> SysResult) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = call);
}
