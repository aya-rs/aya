//! mmap/munmap syscall wrappers and a RAII wrapper around memory-mapped files.

use std::{
    fs, io,
    os::fd::{AsFd as _, BorrowedFd},
    path::Path,
    ptr,
};

use libc::{MAP_FAILED, MAP_PRIVATE, PROT_READ, c_int, c_void, off_t};

use super::SyscallError;

#[cfg_attr(test, expect(unused_variables))]
pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: BorrowedFd<'_>,
    offset: libc::off_t,
) -> *mut c_void {
    #[cfg(test)]
    {
        super::TEST_MMAP_RET.with(|ret| *ret.borrow())
    }

    #[cfg(not(test))]
    {
        use std::os::fd::AsRawFd as _;

        unsafe { libc::mmap(addr, len, prot, flags, fd.as_raw_fd(), offset) }
    }
}

#[cfg_attr(test, expect(unused_variables))]
pub(crate) unsafe fn munmap(addr: *mut c_void, len: usize) -> c_int {
    #[cfg(test)]
    {
        0
    }

    #[cfg(not(test))]
    {
        unsafe { libc::munmap(addr, len) }
    }
}

// MMap corresponds to a memory-mapped region.
//
// The data is unmapped in Drop.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct MMap {
    pub(crate) ptr: ptr::NonNull<c_void>,
    pub(crate) len: usize,
}

// Needed because NonNull<T> is !Send and !Sync out of caution that the data
// might be aliased unsafely.
unsafe impl Send for MMap {}
unsafe impl Sync for MMap {}

impl MMap {
    pub(crate) fn new(
        fd: BorrowedFd<'_>,
        len: usize,
        prot: c_int,
        flags: c_int,
        offset: off_t,
    ) -> Result<Self, SyscallError> {
        match unsafe { mmap(ptr::null_mut(), len, prot, flags, fd, offset) } {
            MAP_FAILED => Err(SyscallError {
                call: "mmap",
                io_error: io::Error::last_os_error(),
            }),
            ptr => {
                let ptr = ptr::NonNull::new(ptr).ok_or(
                    // This should never happen, but to be paranoid, and so we never need to talk
                    // about a null pointer, we check it anyway.
                    SyscallError {
                        call: "mmap",
                        io_error: io::Error::other("mmap returned null pointer"),
                    },
                )?;
                Ok(Self { ptr, len })
            }
        }
    }

    /// Maps the file at `path` for reading, using `mmap` with `MAP_PRIVATE`.
    pub(crate) fn mmap_whole_file(path: &Path) -> Result<Self, io::Error> {
        let file = fs::File::open(path)?;
        Self::new(
            file.as_fd(),
            file.metadata()?.len() as usize,
            PROT_READ,
            MAP_PRIVATE,
            0,
        )
        .map_err(|e| e.io_error)
    }
}

impl AsRef<[u8]> for MMap {
    fn as_ref(&self) -> &[u8] {
        let Self { ptr, len } = self;
        unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast(), *len) }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        let Self { ptr, len } = *self;
        unsafe { munmap(ptr.as_ptr(), len) };
    }
}
