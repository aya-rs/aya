use std::{cell::RefCell, ffi::c_void, io, ptr};

use super::{SysResult, Syscall};

type SyscallFn = unsafe fn(Syscall<'_>) -> SysResult;

thread_local! {
    pub(crate) static TEST_SYSCALL: RefCell<SyscallFn> = RefCell::new(test_syscall);
    pub(crate) static TEST_MMAP_RET: RefCell<*mut c_void> = const { RefCell::new(ptr::null_mut()) };
}

unsafe fn test_syscall(_call: Syscall<'_>) -> SysResult {
    Err((-1, io::Error::from_raw_os_error(libc::EINVAL)))
}

/// Overrides the syscall implementation for testing purposes.
///
/// This function replaces the BPF syscall with a user-provided function,
/// allowing tests to intercept and mock kernel interactions.
///
/// # Example
///
/// ```ignore
/// use aya::sys::test_utils::{override_syscall, Syscall};
///
/// override_syscall(|call| match call {
///     Syscall::Ebpf { cmd, attr } => Ok(0),
///     _ => Ok(0),
/// });
/// ```
#[cfg_attr(
    not(feature = "test-utils"),
    expect(
        unreachable_pub,
        reason = "pub for re-export from sys::test_utils when feature is enabled"
    )
)]
pub fn override_syscall(call: unsafe fn(Syscall<'_>) -> SysResult) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = call);
}
