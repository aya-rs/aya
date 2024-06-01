use std::{
    cmp,
    ffi::{c_char, CStr, CString},
    mem,
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd, RawFd},
    slice,
};

use super::{
    object::bpf_obj_get_info_by_fd,
    utils::{fd_sys_bpf, iter_obj_ids, sys_bpf},
};
use crate::{
    generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_insn, bpf_prog_info, bpf_prog_type},
    obj::btf::{FuncSecInfo, LineSecInfo},
    sys::{SysResult, SyscallError},
    VerifierLogLevel,
};

pub(crate) struct EbpfLoadProgramAttrs<'a> {
    pub(crate) name: Option<CString>,
    pub(crate) ty: bpf_prog_type,
    pub(crate) insns: &'a [bpf_insn],
    pub(crate) license: &'a CStr,
    pub(crate) kernel_version: u32,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) prog_btf_fd: Option<BorrowedFd<'a>>,
    pub(crate) attach_btf_obj_fd: Option<BorrowedFd<'a>>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<BorrowedFd<'a>>,
    pub(crate) func_info_rec_size: usize,
    pub(crate) func_info: FuncSecInfo,
    pub(crate) line_info_rec_size: usize,
    pub(crate) line_info: LineSecInfo,
    pub(crate) flags: u32,
}

pub(crate) fn bpf_load_program(
    aya_attr: &EbpfLoadProgramAttrs<'_>,
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
) -> SysResult<OwnedFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_3 };

    if let Some(prog_name) = &aya_attr.name {
        let mut name: [c_char; 16] = [0; 16];
        let name_bytes = prog_name.to_bytes();
        let len = cmp::min(name.len(), name_bytes.len());
        name[..len].copy_from_slice(unsafe {
            slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, len)
        });
        u.prog_name = name;
    }

    u.prog_flags = aya_attr.flags;
    u.prog_type = aya_attr.ty as u32;
    if let Some(v) = aya_attr.expected_attach_type {
        u.expected_attach_type = v as u32;
    }
    u.insns = aya_attr.insns.as_ptr() as u64;
    u.insn_cnt = aya_attr.insns.len() as u32;
    u.license = aya_attr.license.as_ptr() as u64;
    u.kern_version = aya_attr.kernel_version;

    // these must be allocated here to ensure the slice outlives the pointer
    // so .as_ptr below won't point to garbage
    let line_info_buf = aya_attr.line_info.line_info_bytes();
    let func_info_buf = aya_attr.func_info.func_info_bytes();

    if let Some(btf_fd) = aya_attr.prog_btf_fd {
        u.prog_btf_fd = btf_fd.as_raw_fd() as u32;
        if aya_attr.line_info_rec_size > 0 {
            u.line_info = line_info_buf.as_ptr() as *const _ as u64;
            u.line_info_cnt = aya_attr.line_info.len() as u32;
            u.line_info_rec_size = aya_attr.line_info_rec_size as u32;
        }
        if aya_attr.func_info_rec_size > 0 {
            u.func_info = func_info_buf.as_ptr() as *const _ as u64;
            u.func_info_cnt = aya_attr.func_info.len() as u32;
            u.func_info_rec_size = aya_attr.func_info_rec_size as u32;
        }
    }
    if !log_buf.is_empty() {
        u.log_level = verifier_log_level.bits();
        u.log_buf = log_buf.as_mut_ptr() as u64;
        u.log_size = log_buf.len() as u32;
    }
    if let Some(v) = aya_attr.attach_btf_obj_fd {
        u.__bindgen_anon_1.attach_btf_obj_fd = v.as_raw_fd() as _;
    }
    if let Some(v) = aya_attr.attach_prog_fd {
        u.__bindgen_anon_1.attach_prog_fd = v.as_raw_fd() as u32;
    }

    if let Some(v) = aya_attr.attach_btf_id {
        u.attach_btf_id = v;
    }
    bpf_prog_load(&mut attr)
}

pub(super) fn bpf_prog_load(attr: &mut bpf_attr) -> SysResult<OwnedFd> {
    // SAFETY: BPF_PROG_LOAD returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_PROG_LOAD, attr) }
}

pub(crate) fn bpf_prog_attach(
    prog_fd: BorrowedFd<'_>,
    target_fd: BorrowedFd<'_>,
    attach_type: bpf_attach_type,
) -> Result<(), SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = target_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_ATTACH, &mut attr).map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_prog_attach",
            io_error,
        }
    })?;
    assert_eq!(ret, 0);
    Ok(())
}

pub(crate) fn bpf_prog_detach(
    prog_fd: BorrowedFd<'_>,
    target_fd: BorrowedFd<'_>,
    attach_type: bpf_attach_type,
) -> Result<(), SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = target_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_DETACH, &mut attr).map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_prog_detach",
            io_error,
        }
    })?;
    assert_eq!(ret, 0);
    Ok(())
}

pub(crate) fn iter_prog_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_PROG_GET_NEXT_ID, "bpf_prog_get_next_id")
}

pub(crate) fn bpf_prog_get_fd_by_id(prog_id: u32) -> Result<OwnedFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = prog_id;
    // SAFETY: BPF_PROG_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_prog_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_prog_get_info_by_fd(
    fd: BorrowedFd<'_>,
    map_ids: &mut [u32],
) -> Result<bpf_prog_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |info: &mut bpf_prog_info| {
        info.nr_map_ids = map_ids.len() as _;
        info.map_ids = map_ids.as_mut_ptr() as _;
    })
}

pub(crate) fn bpf_prog_query(
    target_fd: RawFd,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: Option<&mut u32>,
    prog_ids: &mut [u32],
    prog_cnt: &mut u32,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.query.__bindgen_anon_1.target_fd = target_fd as u32;
    attr.query.attach_type = attach_type as u32;
    attr.query.query_flags = query_flags;
    attr.query.__bindgen_anon_2.prog_cnt = prog_ids.len() as u32;
    attr.query.prog_ids = prog_ids.as_mut_ptr() as u64;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_QUERY, &mut attr);

    *prog_cnt = unsafe { attr.query.__bindgen_anon_2.prog_cnt };

    if let Some(attach_flags) = attach_flags {
        *attach_flags = unsafe { attr.query.attach_flags };
    }

    ret
}
