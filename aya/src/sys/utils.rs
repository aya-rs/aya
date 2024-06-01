use std::{
    ffi::CStr,
    io, iter,
    mem::{self, MaybeUninit},
    os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
};

use libc::ENOENT;

use crate::{
    generated::{bpf_attr, bpf_cmd},
    sys::{syscall, SysResult, Syscall, SyscallError},
    Pod,
};

pub(crate) fn bpf_raw_tracepoint_open(
    name: Option<&CStr>,
    prog_fd: BorrowedFd<'_>,
) -> SysResult<OwnedFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.raw_tracepoint.name = match name {
        Some(n) => n.as_ptr() as u64,
        None => 0,
    };
    attr.raw_tracepoint.prog_fd = prog_fd.as_raw_fd() as u32;

    // SAFETY: BPF_RAW_TRACEPOINT_OPEN returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_RAW_TRACEPOINT_OPEN, &mut attr) }
}

pub(super) fn lookup<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    flags: u64,
    cmd: bpf_cmd,
) -> SysResult<Option<V>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut value = MaybeUninit::zeroed();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = &mut value as *mut _ as u64;
    u.flags = flags;

    match sys_bpf(cmd, &mut attr) {
        Ok(_) => Ok(Some(unsafe { value.assume_init() })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(super) fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> SysResult<i64> {
    syscall(Syscall::Ebpf { cmd, attr })
}

// SAFETY: only use for bpf_cmd that return a new file descriptor on success.
pub(super) unsafe fn fd_sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> SysResult<OwnedFd> {
    let fd = sys_bpf(cmd, attr)?;
    let fd = fd.try_into().map_err(|_| {
        (
            fd,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{cmd:?}: invalid fd returned: {fd}"),
            ),
        )
    })?;
    Ok(OwnedFd::from_raw_fd(fd))
}

pub(super) fn iter_obj_ids(
    cmd: bpf_cmd,
    name: &'static str,
) -> impl Iterator<Item = Result<u32, SyscallError>> {
    let mut current_id = Some(0);
    iter::from_fn(move || {
        let next_id = {
            let current_id = current_id?;
            bpf_obj_get_next_id(current_id, cmd, name).transpose()
        };
        current_id = next_id.as_ref().and_then(|next_id| match next_id {
            Ok(next_id) => Some(*next_id),
            Err(SyscallError { .. }) => None,
        });
        next_id
    })
}

fn bpf_obj_get_next_id(
    id: u32,
    cmd: bpf_cmd,
    name: &'static str,
) -> Result<Option<u32>, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_6 };
    u.__bindgen_anon_1.start_id = id;
    match sys_bpf(cmd, &mut attr) {
        Ok(code) => {
            assert_eq!(code, 0);
            Ok(Some(unsafe { attr.__bindgen_anon_6.next_id }))
        }
        Err((code, io_error)) => {
            assert_eq!(code, -1);
            if io_error.raw_os_error() == Some(ENOENT) {
                Ok(None)
            } else {
                Err(SyscallError {
                    call: name,
                    io_error,
                })
            }
        }
    }
}
