use std::{cell::RefCell, collections::VecDeque, ffi::c_void, io, ptr};

use super::{SysResult, Syscall};

type SyscallFn = unsafe fn(Syscall<'_>) -> SysResult;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SYSCALL: RefCell<SyscallFn> = RefCell::new(test_syscall);
    pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = const { RefCell::new(ptr::null_mut()) };
    pub(crate) static TEST_MMAP_RET_QUEUE: RefCell<VecDeque<*mut c_void>> =
        RefCell::new(VecDeque::new());
}

#[cfg(test)]
unsafe fn test_syscall(_call: Syscall<'_>) -> SysResult {
    Err((-1, io::Error::from_raw_os_error(libc::EINVAL)))
}

#[cfg(test)]
pub(crate) fn override_syscall(call: unsafe fn(Syscall<'_>) -> SysResult) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = call);
}

#[cfg(test)]
pub(crate) fn push_test_mmap_ret(ptr: *mut c_void) {
    TEST_MMAP_RET_QUEUE.with(|queue| queue.borrow_mut().push_back(ptr));
}

#[cfg(test)]
pub(crate) fn clear_test_mmap_ret_queue() {
    TEST_MMAP_RET_QUEUE.with(|queue| queue.borrow_mut().clear());
}
