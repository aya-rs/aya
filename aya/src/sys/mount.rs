//! Wrappers for the mount API used to set up BPF filesystems.

use std::{
    ffi::CStr,
    io,
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
    ptr,
};

// https://github.com/torvalds/linux/blob/a38297e3f/include/uapi/linux/mount.h#L83-L111
const FSOPEN_CLOEXEC: libc::c_uint = 0x1;
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const FSMOUNT_CLOEXEC: libc::c_uint = 0x1;

fn fd_result(ret: libc::c_long) -> io::Result<OwnedFd> {
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(ret).map_err(io::Error::other)?;
    // SAFETY: the syscall returned a new file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn unit_result(ret: libc::c_long) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn fsopen(fs_name: &CStr) -> io::Result<OwnedFd> {
    fd_result(unsafe { libc::syscall(libc::SYS_fsopen, fs_name.as_ptr(), FSOPEN_CLOEXEC) })
}

pub(crate) fn fsconfig_set_string(
    fs_fd: BorrowedFd<'_>,
    key: &CStr,
    value: &CStr,
) -> io::Result<()> {
    unit_result(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_fd.as_raw_fd(),
            FSCONFIG_SET_STRING,
            key.as_ptr(),
            value.as_ptr(),
            0,
        )
    })
}

pub(crate) fn fsconfig_create(fs_fd: BorrowedFd<'_>) -> io::Result<()> {
    unit_result(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_fd.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        )
    })
}

pub(crate) fn fsmount(fs_fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    fd_result(unsafe { libc::syscall(libc::SYS_fsmount, fs_fd.as_raw_fd(), FSMOUNT_CLOEXEC, 0) })
}
