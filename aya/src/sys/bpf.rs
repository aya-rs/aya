use std::{
    cmp,
    ffi::CStr,
    io,
    mem::{self, MaybeUninit},
    os::unix::io::RawFd,
    slice,
};

use libc::{c_long, ENOENT};

use crate::{
    bpf_map_def,
    generated::{bpf_attach_type, bpf_attr, bpf_cmd, bpf_insn, bpf_prog_info, bpf_prog_type},
    maps::PerCpuValues,
    programs::VerifierLog,
    sys::SysResult,
    Pod, BPF_OBJ_NAME_LEN,
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

pub(crate) fn bpf_pin_object(fd: RawFd, path: &CStr) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.bpf_fd = fd as u32;
    u.pathname = path.as_ptr() as u64;
    sys_bpf(bpf_cmd::BPF_OBJ_PIN, &attr)
}

pub(crate) fn bpf_get_object(path: &CStr) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.pathname = path.as_ptr() as u64;
    sys_bpf(bpf_cmd::BPF_OBJ_GET, &attr)
}

pub(crate) fn bpf_load_program(
    ty: bpf_prog_type,
    insns: &[bpf_insn],
    license: &CStr,
    kernel_version: u32,
    log: &mut VerifierLog,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_3 };
    u.prog_type = ty as u32;
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
    key: Option<&K>,
    flags: u64,
    cmd: bpf_cmd,
) -> Result<Option<V>, (c_long, io::Error)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut value = MaybeUninit::zeroed();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
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
    lookup(fd, Some(key), flags, bpf_cmd::BPF_MAP_LOOKUP_ELEM)
}

pub(crate) fn bpf_map_lookup_and_delete_elem<K: Pod, V: Pod>(
    fd: RawFd,
    key: Option<&K>,
    flags: u64,
) -> Result<Option<V>, (c_long, io::Error)> {
    lookup(fd, key, flags, bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM)
}

pub(crate) fn bpf_map_lookup_elem_per_cpu<K: Pod, V: Pod>(
    fd: RawFd,
    key: &K,
    flags: u64,
) -> Result<Option<PerCpuValues<V>>, (c_long, io::Error)> {
    let mut mem = PerCpuValues::<V>::alloc_kernel_mem().map_err(|io_error| (-1, io_error))?;
    match bpf_map_lookup_elem_ptr(fd, key, mem.as_mut_ptr(), flags) {
        Ok(_) => Ok(Some(unsafe { PerCpuValues::from_kernel_mem(mem) })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem_ptr<K: Pod, V>(
    fd: RawFd,
    key: &K,
    value: *mut V,
    flags: u64,
) -> Result<Option<()>, (c_long, io::Error)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.key = key as *const _ as u64;
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    match sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_ELEM, &attr) {
        Ok(_) => Ok(Some(())),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
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

pub(crate) fn bpf_map_push_elem<V>(fd: RawFd, value: &V, flags: u64) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &attr)
}

pub(crate) fn bpf_map_update_elem_ptr<K, V>(
    fd: RawFd,
    key: *const K,
    value: *mut V,
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

pub(crate) fn bpf_map_update_elem_per_cpu<K, V: Pod>(
    fd: RawFd,
    key: &K,
    values: &PerCpuValues<V>,
    flags: u64,
) -> SysResult {
    let mut mem = values.build_kernel_mem().map_err(|e| (-1, e))?;
    bpf_map_update_elem_ptr(fd, key, mem.as_mut_ptr(), flags)
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
    attach_type: bpf_attach_type,
    flags: u32,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_create.prog_fd = prog_fd as u32;
    attr.link_create.__bindgen_anon_1.target_fd = target_fd as u32;
    attr.link_create.attach_type = attach_type as u32;
    attr.link_create.flags = flags;

    sys_bpf(bpf_cmd::BPF_LINK_CREATE, &attr)
}

pub(crate) fn bpf_prog_attach(
    prog_fd: RawFd,
    target_fd: RawFd,
    attach_type: bpf_attach_type,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd as u32;
    attr.__bindgen_anon_5.target_fd = target_fd as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;

    sys_bpf(bpf_cmd::BPF_PROG_ATTACH, &attr)
}

pub(crate) fn bpf_prog_detach(
    prog_fd: RawFd,
    map_fd: RawFd,
    attach_type: bpf_attach_type,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd as u32;
    attr.__bindgen_anon_5.target_fd = map_fd as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;

    sys_bpf(bpf_cmd::BPF_PROG_DETACH, &attr)
}

pub(crate) fn bpf_prog_query(
    target_fd: RawFd,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: Option<&mut u32>,
    prog_ids: &mut [u32],
    prog_cnt: &mut u32,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.query.target_fd = target_fd as u32;
    attr.query.attach_type = attach_type as u32;
    attr.query.query_flags = query_flags;
    attr.query.prog_cnt = prog_ids.len() as u32;
    attr.query.prog_ids = prog_ids.as_mut_ptr() as u64;

    let ret = sys_bpf(bpf_cmd::BPF_PROG_QUERY, &attr);

    *prog_cnt = unsafe { attr.query.prog_cnt };

    if let Some(attach_flags) = attach_flags {
        *attach_flags = unsafe { attr.query.attach_flags };
    }

    ret
}

pub(crate) fn bpf_prog_get_fd_by_id(prog_id: u32) -> Result<RawFd, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = prog_id;

    match sys_bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &attr) {
        Ok(v) => Ok(v as RawFd),
        Err((_, err)) => Err(err),
    }
}

pub(crate) fn bpf_obj_get_info_by_fd(prog_fd: RawFd) -> Result<bpf_prog_info, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // info gets entirely populated by the kernel
    let info = unsafe { MaybeUninit::zeroed().assume_init() };

    attr.info.bpf_fd = prog_fd as u32;
    attr.info.info = &info as *const _ as u64;
    attr.info.info_len = mem::size_of::<bpf_prog_info>() as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &attr) {
        Ok(_) => Ok(info),
        Err((_, err)) => Err(err),
    }
}

fn sys_bpf(cmd: bpf_cmd, attr: &bpf_attr) -> SysResult {
    syscall(Syscall::Bpf { cmd, attr })
}
