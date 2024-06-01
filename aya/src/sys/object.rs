use std::{
    ffi::CStr,
    mem,
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd},
};

use aya_obj::generated::bpf_btf_info;

use super::utils::{fd_sys_bpf, sys_bpf};
use crate::{
    generated::{bpf_attr, bpf_cmd},
    sys::{SysResult, SyscallError},
};

pub(crate) fn bpf_pin_object(fd: BorrowedFd<'_>, path: &CStr) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.bpf_fd = fd.as_raw_fd() as u32;
    u.pathname = path.as_ptr() as u64;
    sys_bpf(bpf_cmd::BPF_OBJ_PIN, &mut attr)
}

pub(crate) fn bpf_get_object(path: &CStr) -> SysResult<OwnedFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.pathname = path.as_ptr() as u64;
    // SAFETY: BPF_OBJ_GET returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_OBJ_GET, &mut attr) }
}

pub(super) fn bpf_obj_get_info_by_fd<T, F: FnOnce(&mut T)>(
    fd: BorrowedFd<'_>,
    init: F,
) -> Result<T, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut info = unsafe { mem::zeroed() };

    init(&mut info);

    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info = &info as *const _ as u64;
    attr.info.info_len = mem::size_of_val(&info) as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
        Ok(code) => {
            assert_eq!(code, 0);
            Ok(info)
        }
        Err((code, io_error)) => {
            assert_eq!(code, -1);
            Err(SyscallError {
                call: "bpf_obj_get_info_by_fd",
                io_error,
            })
        }
    }
}

pub(crate) fn btf_obj_get_info_by_fd(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
) -> Result<bpf_btf_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |info: &mut bpf_btf_info| {
        info.btf = buf.as_mut_ptr() as _;
        info.btf_size = buf.len() as _;
    })
}
