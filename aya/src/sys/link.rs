use std::{
    mem,
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd, RawFd},
};

use super::{
    object::bpf_obj_get_info_by_fd,
    utils::{fd_sys_bpf, iter_obj_ids, sys_bpf},
};
use crate::{
    generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_link_info, BPF_F_REPLACE},
    sys::{SysResult, SyscallError},
};

pub(crate) enum LinkTarget<'f> {
    Fd(BorrowedFd<'f>),
    IfIndex(u32),
}

// since kernel 5.7
pub(crate) fn bpf_link_create(
    prog_fd: BorrowedFd<'_>,
    target: LinkTarget<'_>,
    attach_type: bpf_attach_type,
    btf_id: Option<u32>,
    flags: u32,
) -> SysResult<OwnedFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_create.__bindgen_anon_1.prog_fd = prog_fd.as_raw_fd() as u32;

    match target {
        LinkTarget::Fd(fd) => {
            attr.link_create.__bindgen_anon_2.target_fd = fd.as_raw_fd() as u32;
        }
        LinkTarget::IfIndex(ifindex) => {
            attr.link_create.__bindgen_anon_2.target_ifindex = ifindex;
        }
    };
    attr.link_create.attach_type = attach_type as u32;
    attr.link_create.flags = flags;
    if let Some(btf_id) = btf_id {
        attr.link_create.__bindgen_anon_3.target_btf_id = btf_id;
    }

    // SAFETY: BPF_LINK_CREATE returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_LINK_CREATE, &mut attr) }
}

// since kernel 5.7
pub(crate) fn bpf_link_update(
    link_fd: BorrowedFd<'_>,
    new_prog_fd: BorrowedFd<'_>,
    old_prog_fd: Option<RawFd>,
    flags: u32,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_update.link_fd = link_fd.as_raw_fd() as u32;
    attr.link_update.__bindgen_anon_1.new_prog_fd = new_prog_fd.as_raw_fd() as u32;
    if let Some(fd) = old_prog_fd {
        attr.link_update.__bindgen_anon_2.old_prog_fd = fd as u32;
        attr.link_update.flags = flags | BPF_F_REPLACE;
    } else {
        attr.link_update.flags = flags;
    }

    sys_bpf(bpf_cmd::BPF_LINK_UPDATE, &mut attr)
}

pub(crate) fn bpf_link_get_fd_by_id(link_id: u32) -> Result<OwnedFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.link_id = link_id;
    // SAFETY: BPF_LINK_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_LINK_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_link_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn iter_link_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_LINK_GET_NEXT_ID, "bpf_link_get_next_id")
}

pub(crate) fn bpf_link_get_info_by_fd(fd: BorrowedFd<'_>) -> Result<bpf_link_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |_| {})
}
