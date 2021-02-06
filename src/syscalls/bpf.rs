use std::{
    cmp,
    ffi::CStr,
    io,
    mem::{self, MaybeUninit},
    slice,
};

use libc::{c_long, c_uint, ENOENT};

use crate::{
    bpf_map_def,
    generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_insn},
    programs::VerifierLog,
    syscalls::SysResult,
    Pod, RawFd, BPF_OBJ_NAME_LEN,
};

use super::{syscall, Syscall};

pub(crate) fn bpf_create_map(name: &CStr, def: &bpf_map_def) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = def.map_type;
    u.key_size = def.key_size;
    u.value_size = def.value_size;
    u.max_entries = def.max_entries;
    u.map_flags = def.map_flags;

    // u.map_name is 16 bytes max and must be NULL terminated
    let name_len = cmp::min(name.to_bytes().len(), BPF_OBJ_NAME_LEN - 1);
    u.map_name[..name_len]
        .copy_from_slice(unsafe { slice::from_raw_parts(name.as_ptr(), name_len) });

    sys_bpf(bpf_cmd::BPF_MAP_CREATE, &attr)
}

pub(crate) fn bpf_load_program(
    ty: c_uint,
    insns: &[bpf_insn],
    license: &CStr,
    kernel_version: u32,
    log: &mut VerifierLog,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_3 };
    u.prog_type = ty;
    u.expected_attach_type = 0;
    u.insns = insns.as_ptr() as u64;
    u.insn_cnt = insns.len() as u32;
    u.license = license.as_ptr() as u64;
    u.kern_version = kernel_version;
    let log_buf = log.buf();
    if log_buf.capacity() > 0 {
        u.log_level = 7;
        u.log_buf = log_buf.as_mut_ptr() as u64;
        u.log_size = log_buf.capacity() as u32;
    }

    sys_bpf(bpf_cmd::BPF_PROG_LOAD, &attr)
}

fn lookup<K: Pod, V: Pod>(
    fd: RawFd,
    key: &K,
    flags: u64,
    cmd: bpf_cmd::Type,
) -> Result<Option<V>, (c_long, io::Error)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut value = MaybeUninit::uninit();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.key = key as *const _ as u64;
    u.__bindgen_anon_1.value = &mut value as *mut _ as u64;
    u.flags = flags;

    match sys_bpf(cmd, &attr) {
        Ok(_) => Ok(Some(unsafe { value.assume_init() })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem<K: Pod, V: Pod>(
    fd: RawFd,
    key: &K,
    flags: u64,
) -> Result<Option<V>, (c_long, io::Error)> {
    lookup(fd, key, flags, bpf_cmd::BPF_MAP_LOOKUP_ELEM)
}

pub(crate) fn bpf_map_lookup_and_delete_elem<K: Pod, V: Pod>(
    fd: RawFd,
    key: &K,
) -> Result<Option<V>, (c_long, io::Error)> {
    lookup(fd, key, 0, bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM)
}

pub(crate) fn bpf_map_update_elem<K, V>(fd: RawFd, key: &K, value: &V, flags: u64) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.key = key as *const _ as u64;
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &attr)
}

pub(crate) fn bpf_map_update_elem_ptr<K, V>(
    fd: RawFd,
    key: *const K,
    value: *const V,
    flags: u64,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.key = key as u64;
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &attr)
}

pub(crate) fn bpf_map_delete_elem<K>(fd: RawFd, key: &K) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.key = key as *const _ as u64;

    sys_bpf(bpf_cmd::BPF_MAP_DELETE_ELEM, &attr)
}

pub(crate) fn bpf_map_get_next_key<K>(
    fd: RawFd,
    key: Option<&K>,
) -> Result<Option<K>, (c_long, io::Error)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut next_key = MaybeUninit::uninit();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.next_key = &mut next_key as *mut _ as u64;

    match sys_bpf(bpf_cmd::BPF_MAP_GET_NEXT_KEY, &attr) {
        Ok(_) => Ok(Some(unsafe { next_key.assume_init() })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

// since kernel 5.7
pub(crate) fn bpf_link_create(
    prog_fd: RawFd,
    target_fd: RawFd,
    attach_type: bpf_attach_type::Type,
    flags: u32,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_create.prog_fd = prog_fd as u32;
    attr.link_create.__bindgen_anon_1.target_fd = target_fd as u32;
    attr.link_create.attach_type = attach_type;
    attr.link_create.flags = flags;

    sys_bpf(bpf_cmd::BPF_LINK_CREATE, &attr)
}

fn sys_bpf<'a>(cmd: bpf_cmd::Type, attr: &'a bpf_attr) -> SysResult {
    syscall(Syscall::Bpf { cmd, attr })
}
