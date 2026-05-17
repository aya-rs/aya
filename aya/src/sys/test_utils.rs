//! Test utilities for mocking BPF syscalls.
//!
//! This module is only available when the `test-utils` feature is enabled.
//! It provides [`override_syscall`] to intercept BPF syscalls in tests,
//! allowing userspace code to be tested without a real kernel.
//!
//! # Example
//!
//! ```ignore
//! use aya::sys::test_utils::{override_syscall, Syscall, bpf_cmd};
//!
//! override_syscall(|call| match call {
//!     Syscall::Ebpf { cmd, attr } => {
//!         // Handle BPF syscalls
//!         Ok(0)
//!     }
//!     _ => Ok(0),
//! });
//! ```

use std::{cell::RefCell, ffi::c_void, io, ptr};

pub use aya_obj::generated::{bpf_attr, bpf_cmd};

pub use super::{PerfEventIoctlRequest, SysResult, Syscall};

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
pub fn override_syscall(call: unsafe fn(Syscall<'_>) -> SysResult) {
    TEST_SYSCALL.with(|test_impl| *test_impl.borrow_mut() = call);
}

/// Returns the fake file descriptor value used internally by Aya's test
/// infrastructure. Return this from your [`override_syscall`] handler for
/// syscalls that create FDs (e.g. `BPF_MAP_CREATE`).
pub const fn mock_fd() -> i32 {
    crate::MockableFd::mock_signed_fd()
}
