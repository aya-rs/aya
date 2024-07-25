mod bpf;
mod netlink;
mod perf_event;

#[cfg(test)]
mod fake;

use std::{
    ffi::{c_int, c_uint, c_void},
    io, mem,
    os::fd::{AsRawFd as _, BorrowedFd},
};

pub(crate) use bpf::*;
pub use bpf::{create_bpf_filesystem, FilesystemPermissions, FilesystemPermissionsBuilder};
#[cfg(test)]
pub(crate) use fake::*;
use libc::{
    c_char, pid_t, SYS_bpf, SYS_fsconfig, SYS_fsmount, SYS_fsopen, SYS_move_mount,
    SYS_perf_event_open,
};
#[doc(hidden)]
pub use netlink::netlink_set_link_up;
pub(crate) use netlink::*;
pub(crate) use perf_event::*;
use thiserror::Error;

use crate::generated::{bpf_attr, bpf_cmd, perf_event_attr};

pub(crate) type SysResult<T> = Result<T, (i64, io::Error)>;

pub(crate) enum Syscall<'a> {
    Ebpf {
        cmd: bpf_cmd,
        attr: &'a mut bpf_attr,
    },
    PerfEventOpen {
        attr: perf_event_attr,
        pid: pid_t,
        cpu: i32,
        group: i32,
        flags: u32,
    },
    PerfEventIoctl {
        fd: BorrowedFd<'a>,
        request: c_int,
        arg: c_int,
    },
    FsOpen {
        fsname: *const c_char,
        flags: u32,
    },
    FsMount {
        fd: BorrowedFd<'a>,
        flags: c_uint,
        mount_attrs: c_uint,
    },
    FsConfig {
        fd: BorrowedFd<'a>,
        cmd: c_uint,
        key: *const c_char,
        value: *const c_void,
        aux: c_int,
    },
    MoveMount {
        from_dirfd: BorrowedFd<'a>,
        from_pathname: *const c_char,
        to_dirfd: BorrowedFd<'a>,
        to_pathname: *const c_char,
        flags: u32,
    },
}

#[derive(Debug, Error)]
#[error("`{call}` failed")]
pub struct SyscallError {
    /// The name of the syscall which failed.
    pub call: &'static str,
    /// The [`io::Error`] returned by the syscall.
    #[source]
    pub io_error: io::Error,
}

impl std::fmt::Debug for Syscall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ebpf { cmd, attr: _ } => f
                .debug_struct("Syscall::Ebpf")
                .field("cmd", cmd)
                .field("attr", &format_args!("_"))
                .finish(),
            Self::PerfEventOpen {
                attr: _,
                pid,
                cpu,
                group,
                flags,
            } => f
                .debug_struct("Syscall::PerfEventOpen")
                .field("attr", &format_args!("_"))
                .field("pid", pid)
                .field("cpu", cpu)
                .field("group", group)
                .field("flags", flags)
                .finish(),
            Self::PerfEventIoctl { fd, request, arg } => f
                .debug_struct("Syscall::PerfEventIoctl")
                .field("fd", fd)
                .field("request", request)
                .field("arg", arg)
                .finish(),
            Self::FsOpen { fsname, flags } => f
                .debug_struct("Syscall::FsOpen")
                .field("fsname", fsname)
                .field("flags", flags)
                .finish(),
            Self::FsMount {
                fd,
                flags,
                mount_attrs,
            } => f
                .debug_struct("Syscall::FsMount")
                .field("fd", fd)
                .field("flags", flags)
                .field("mount_attrs", mount_attrs)
                .finish(),
            Self::FsConfig {
                fd,
                cmd,
                key,
                value,
                aux,
            } => f
                .debug_struct("Syscall::FsConfig")
                .field("fd", fd)
                .field("cmd", cmd)
                .field("key", key)
                .field("value", value)
                .field("aux", aux)
                .finish(),
            Self::MoveMount {
                from_dirfd,
                from_pathname,
                to_dirfd,
                to_pathname,
                flags,
            } => f
                .debug_struct("Syscall::MoveMount")
                .field("from_dirfd", from_dirfd)
                .field("from_pathname", from_pathname)
                .field("to_dirfd", to_dirfd)
                .field("to_pathname", to_pathname)
                .field("flags", flags)
                .finish(),
        }
    }
}

fn syscall(call: Syscall<'_>) -> SysResult<i64> {
    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });

    #[cfg_attr(test, allow(unreachable_code))]
    {
        let ret = unsafe {
            match call {
                Syscall::Ebpf { cmd, attr } => {
                    libc::syscall(SYS_bpf, cmd, attr, mem::size_of::<bpf_attr>())
                }
                Syscall::PerfEventOpen {
                    attr,
                    pid,
                    cpu,
                    group,
                    flags,
                } => libc::syscall(SYS_perf_event_open, &attr, pid, cpu, group, flags),
                Syscall::PerfEventIoctl { fd, request, arg } => {
                    let ret = libc::ioctl(fd.as_raw_fd(), request.try_into().unwrap(), arg);
                    // `libc::ioctl` returns i32 on x86_64 while `libc::syscall` returns i64.
                    #[allow(clippy::useless_conversion)]
                    ret.into()
                }
                Syscall::FsOpen { fsname, flags } => libc::syscall(SYS_fsopen, fsname, flags),
                Syscall::FsMount {
                    fd,
                    flags,
                    mount_attrs,
                } => libc::syscall(SYS_fsmount, fd.as_raw_fd(), flags, mount_attrs),
                Syscall::FsConfig {
                    fd,
                    cmd,
                    key,
                    value,
                    aux,
                } => libc::syscall(SYS_fsconfig, fd.as_raw_fd(), cmd, key, value, aux),
                Syscall::MoveMount {
                    from_dirfd,
                    from_pathname,
                    to_dirfd,
                    to_pathname,
                    flags,
                } => libc::syscall(
                    SYS_move_mount,
                    from_dirfd.as_raw_fd(),
                    from_pathname,
                    to_dirfd.as_raw_fd(),
                    to_pathname,
                    flags,
                ),
            }
        };

        // `libc::syscall` returns i32 on armv7.
        #[allow(clippy::useless_conversion)]
        match ret.into() {
            ret @ 0.. => Ok(ret),
            ret => Err((ret, io::Error::last_os_error())),
        }
    }
}

#[cfg_attr(test, allow(unused_variables))]
pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: BorrowedFd<'_>,
    offset: libc::off_t,
) -> *mut c_void {
    #[cfg(not(test))]
    return libc::mmap(addr, len, prot, flags, fd.as_raw_fd(), offset);

    #[cfg(test)]
    TEST_MMAP_RET.with(|ret| *ret.borrow())
}
