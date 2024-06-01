use std::{mem, os::fd::OwnedFd};

use super::utils::fd_sys_bpf;
use crate::{
    generated::{bpf_attr, bpf_cmd},
    sys::{SysResult, SyscallError},
    VerifierLogLevel,
};

pub(crate) fn bpf_load_btf(
    raw_btf: &[u8],
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
) -> SysResult<OwnedFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = raw_btf.as_ptr() as *const _ as u64;
    u.btf_size = mem::size_of_val(raw_btf) as u32;
    if !log_buf.is_empty() {
        u.btf_log_level = verifier_log_level.bits();
        u.btf_log_buf = log_buf.as_mut_ptr() as u64;
        u.btf_log_size = log_buf.len() as u32;
    }
    // SAFETY: `BPF_BTF_LOAD` returns a newly created fd.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_BTF_LOAD, &mut attr) }
}

pub(crate) fn bpf_btf_get_fd_by_id(id: u32) -> Result<OwnedFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;

    // SAFETY: BPF_BTF_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_btf_get_fd_by_id",
            io_error,
        }
    })
}
