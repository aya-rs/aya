mod bpf;
mod netlink;
mod perf_event;

#[cfg(test)]
mod fake;

use std::io;
#[cfg(not(test))]
use std::{ffi::CString, mem};
#[cfg(not(test))]
use std::{fs::File, io::Read};

#[cfg(not(test))]
use libc::utsname;
use libc::{c_int, c_long, c_void, pid_t};

pub(crate) use bpf::*;
#[cfg(test)]
pub(crate) use fake::*;
pub(crate) use netlink::*;
pub(crate) use perf_event::*;

use crate::generated::{bpf_attr, bpf_cmd, perf_event_attr};

pub(crate) type SysResult = Result<c_long, (c_long, io::Error)>;

#[cfg_attr(test, allow(dead_code))]
pub(crate) enum Syscall<'a> {
    Bpf {
        cmd: bpf_cmd,
        attr: &'a bpf_attr,
    },
    PerfEventOpen {
        attr: perf_event_attr,
        pid: pid_t,
        cpu: i32,
        group: i32,
        flags: u32,
    },
    PerfEventIoctl {
        fd: c_int,
        request: c_int,
        arg: c_int,
    },
}

fn syscall(call: Syscall) -> SysResult {
    #[cfg(not(test))]
    return unsafe { syscall_impl(call) };

    #[cfg(test)]
    return TEST_SYSCALL.with(|test_impl| unsafe { test_impl.borrow()(call) });
}

#[cfg(not(test))]
unsafe fn syscall_impl(call: Syscall) -> SysResult {
    use libc::{SYS_bpf, SYS_perf_event_open};

    use Syscall::*;
    let ret = match call {
        Bpf { cmd, attr } => libc::syscall(SYS_bpf, cmd, attr, mem::size_of::<bpf_attr>()),
        PerfEventOpen {
            attr,
            pid,
            cpu,
            group,
            flags,
        } => libc::syscall(SYS_perf_event_open, &attr, pid, cpu, group, flags),
        PerfEventIoctl { fd, request, arg } => {
            libc::ioctl(fd, request.try_into().unwrap(), arg) as libc::c_long
        }
    };

    if ret < 0 {
        return Err((ret, io::Error::last_os_error()));
    }

    Ok(ret)
}

#[cfg(test)]
pub(crate) fn kernel_version() -> Result<(u32, u32, u32), ()> {
    Ok((0xff, 0xff, 0xff))
}

#[cfg(not(test))]
fn ubuntu_kernel_version() -> Result<(u32, u32, u32), ()> {
    if let Ok(mut file) = File::open("/proc/version_signature") {
        let mut buf = String::new();
        let mut major = 0u32;
        let mut minor = 0u32;
        let mut patch = 0u32;
        let format = CString::new("%*s %*s %u.%u.%u\n").unwrap();

        file.read_to_string(&mut buf).map_err(|_| ())?;

        unsafe {
            if libc::sscanf(
                buf.as_ptr() as *const _,
                format.as_ptr(),
                &mut major as *mut u32,
                &mut minor as *mut _,
                &mut patch as *mut _,
            ) == 3
            {
                return Ok((major, minor, patch));
            }
        }
    }

    Err(())
}

#[cfg(not(test))]
pub(crate) fn kernel_version() -> Result<(u32, u32, u32), ()> {
    if let Ok(version) = ubuntu_kernel_version() {
        return Ok(version);
    }

    unsafe {
        let mut v = mem::zeroed::<utsname>();
        if libc::uname(&mut v as *mut _) != 0 {
            return Err(());
        }

        let mut major = 0u32;
        let mut minor = 0u32;
        let mut patch = 0u32;

        let debian_marker = CString::new("Debian").unwrap();

        let p = libc::strstr(v.version.as_ptr(), debian_marker.as_ptr());

        if !p.is_null() {
            let debian_format = CString::new("Debian %u.%u.%u").map_err(|_| ())?;

            if libc::sscanf(
                p,
                debian_format.as_ptr(),
                &mut major as *mut u32,
                &mut minor as *mut _,
                &mut patch as *mut _,
            ) == 3
            {
                // On Debian 10, kernels after 4.19.229 expect 4.19.255 due to broken Makefile patches.
                let patch_level_limit = if major == 4 && minor == 19 { 230 } else { 255 };

                if patch >= patch_level_limit {
                    patch = 255;
                }

                return Ok((major, minor, patch));
            }
        }

        let format = CString::new("%u.%u.%u").unwrap();
        if libc::sscanf(
            v.release.as_ptr(),
            format.as_ptr(),
            &mut major as *mut u32,
            &mut minor as *mut _,
            &mut patch as *mut _,
        ) != 3
        {
            return Err(());
        }

        Ok((major, minor, patch))
    }
}

#[cfg_attr(test, allow(unused_variables))]
pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: i32,
    offset: libc::off_t,
) -> *mut c_void {
    #[cfg(not(test))]
    return libc::mmap(addr, len, prot, flags, fd, offset);

    #[cfg(test)]
    TEST_MMAP_RET.with(|ret| *ret.borrow())
}
