use std::{
    cmp::{self, min},
    ffi::{CStr, CString},
    io,
    mem::{self, MaybeUninit},
    os::unix::io::RawFd,
    slice,
};

use libc::{c_char, c_long, close, ENOENT, ENOSPC};

use crate::{
    generated::{
        bpf_attach_type, bpf_attr, bpf_btf_info, bpf_cmd, bpf_insn, bpf_link_info, bpf_map_info,
        bpf_prog_info, bpf_prog_type, bpf_task_fd_type, BPF_F_REPLACE,
    },
    maps::PerCpuValues,
    obj::{
        self,
        btf::{
            BtfParam, BtfType, DataSec, DataSecEntry, DeclTag, Float, Func, FuncLinkage, FuncProto,
            FuncSecInfo, Int, IntEncoding, LineSecInfo, Ptr, TypeTag, Var, VarLinkage,
        },
        copy_instructions,
    },
    sys::{kernel_version, syscall, SysResult, Syscall},
    util::VerifierLog,
    Btf, Pod, BPF_OBJ_NAME_LEN,
};

pub(crate) fn bpf_create_map(name: &CStr, def: &obj::Map, btf_fd: Option<RawFd>) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = def.map_type();
    u.key_size = def.key_size();
    u.value_size = def.value_size();
    u.max_entries = def.max_entries();
    u.map_flags = def.map_flags();

    if let obj::Map::Btf(m) = def {
        u.btf_key_type_id = m.def.btf_key_type_id;
        u.btf_value_type_id = m.def.btf_value_type_id;
        u.btf_fd = btf_fd.unwrap() as u32;
    }

    // https://github.com/torvalds/linux/commit/ad5b177bd73f5107d97c36f56395c4281fb6f089
    // The map name was added as a parameter in kernel 4.15+ so we skip adding it on
    // older kernels for compatibility
    let k_ver = kernel_version().unwrap();
    if k_ver >= (4, 15, 0) {
        // u.map_name is 16 bytes max and must be NULL terminated
        let name_len = cmp::min(name.to_bytes().len(), BPF_OBJ_NAME_LEN - 1);
        u.map_name[..name_len]
            .copy_from_slice(unsafe { slice::from_raw_parts(name.as_ptr(), name_len) });
    }

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

pub(crate) struct BpfLoadProgramAttrs<'a> {
    pub(crate) name: Option<CString>,
    pub(crate) ty: bpf_prog_type,
    pub(crate) insns: &'a [bpf_insn],
    pub(crate) license: &'a CStr,
    pub(crate) kernel_version: u32,
    pub(crate) expected_attach_type: Option<bpf_attach_type>,
    pub(crate) prog_btf_fd: Option<RawFd>,
    pub(crate) attach_btf_obj_fd: Option<u32>,
    pub(crate) attach_btf_id: Option<u32>,
    pub(crate) attach_prog_fd: Option<RawFd>,
    pub(crate) func_info_rec_size: usize,
    pub(crate) func_info: FuncSecInfo,
    pub(crate) line_info_rec_size: usize,
    pub(crate) line_info: LineSecInfo,
}

pub(crate) fn bpf_load_program(
    aya_attr: &BpfLoadProgramAttrs,
    logger: &mut VerifierLog,
    verifier_log_level: u32,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_3 };

    if let Some(prog_name) = &aya_attr.name {
        let mut name: [c_char; 16] = [0; 16];
        let name_bytes = prog_name.to_bytes();
        let len = min(name.len(), name_bytes.len());
        name[..len].copy_from_slice(unsafe {
            slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, len)
        });
        u.prog_name = name;
    }

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
        u.prog_btf_fd = btf_fd as u32;
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
    let log_buf = logger.buf();
    if log_buf.capacity() > 0 {
        u.log_level = verifier_log_level;
        u.log_buf = log_buf.as_mut_ptr() as u64;
        u.log_size = log_buf.capacity() as u32;
    }
    if let Some(v) = aya_attr.attach_btf_obj_fd {
        u.__bindgen_anon_1.attach_btf_obj_fd = v;
    }
    if let Some(v) = aya_attr.attach_prog_fd {
        u.__bindgen_anon_1.attach_prog_fd = v as u32;
    }

    if let Some(v) = aya_attr.attach_btf_id {
        u.attach_btf_id = v;
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
    match bpf_map_lookup_elem_ptr(fd, Some(key), mem.as_mut_ptr(), flags) {
        Ok(_) => Ok(Some(unsafe { PerCpuValues::from_kernel_mem(mem) })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem_ptr<K: Pod, V>(
    fd: RawFd,
    key: Option<&K>,
    value: *mut V,
    flags: u64,
) -> Result<Option<()>, (c_long, io::Error)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    match sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_ELEM, &attr) {
        Ok(_) => Ok(Some(())),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_update_elem<K: Pod, V: Pod>(
    fd: RawFd,
    key: Option<&K>,
    value: &V,
    flags: u64,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &attr)
}

pub(crate) fn bpf_map_push_elem<V: Pod>(fd: RawFd, value: &V, flags: u64) -> SysResult {
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

pub(crate) fn bpf_map_update_elem_per_cpu<K: Pod, V: Pod>(
    fd: RawFd,
    key: &K,
    values: &PerCpuValues<V>,
    flags: u64,
) -> SysResult {
    let mut mem = values.build_kernel_mem().map_err(|e| (-1, e))?;
    bpf_map_update_elem_ptr(fd, key, mem.as_mut_ptr(), flags)
}

pub(crate) fn bpf_map_delete_elem<K: Pod>(fd: RawFd, key: &K) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    u.key = key as *const _ as u64;

    sys_bpf(bpf_cmd::BPF_MAP_DELETE_ELEM, &attr)
}

pub(crate) fn bpf_map_get_next_key<K: Pod>(
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

// since kernel 5.2
pub(crate) fn bpf_map_freeze(fd: RawFd) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd as u32;
    sys_bpf(bpf_cmd::BPF_MAP_FREEZE, &attr)
}

// since kernel 5.7
pub(crate) fn bpf_link_create(
    prog_fd: RawFd,
    target_fd: RawFd,
    attach_type: bpf_attach_type,
    btf_id: Option<u32>,
    flags: u32,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_create.prog_fd = prog_fd as u32;
    attr.link_create.__bindgen_anon_1.target_fd = target_fd as u32;
    attr.link_create.attach_type = attach_type as u32;
    attr.link_create.flags = flags;
    if let Some(btf_id) = btf_id {
        attr.link_create.__bindgen_anon_2.target_btf_id = btf_id;
    }

    sys_bpf(bpf_cmd::BPF_LINK_CREATE, &attr)
}

// since kernel 5.7
pub(crate) fn bpf_link_update(
    link_fd: RawFd,
    new_prog_fd: RawFd,
    old_prog_fd: Option<RawFd>,
    flags: u32,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_update.link_fd = link_fd as u32;
    attr.link_update.new_prog_fd = new_prog_fd as u32;
    if let Some(fd) = old_prog_fd {
        attr.link_update.old_prog_fd = fd as u32;
        attr.link_update.flags = flags | BPF_F_REPLACE;
    } else {
        attr.link_update.flags = flags;
    }

    sys_bpf(bpf_cmd::BPF_LINK_UPDATE, &attr)
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

pub(crate) fn bpf_prog_get_info_by_fd(prog_fd: RawFd) -> Result<bpf_prog_info, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // info gets entirely populated by the kernel
    let info = MaybeUninit::zeroed();

    attr.info.bpf_fd = prog_fd as u32;
    attr.info.info = &info as *const _ as u64;
    attr.info.info_len = mem::size_of::<bpf_prog_info>() as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &attr) {
        Ok(_) => Ok(unsafe { info.assume_init() }),
        Err((_, err)) => Err(err),
    }
}

#[derive(Debug)]
pub(crate) struct TaskFdQueryOutput<'buf> {
    pub(crate) prog_id: u32,
    pub(crate) fd_type: bpf_task_fd_type,
    pub(crate) name: Option<&'buf CStr>,
    pub(crate) probe_offset: Option<u64>,
    pub(crate) probe_addr: Option<u64>,
}

pub(crate) fn bpf_task_fd_query<'buf>(
    pid: u32,
    target_fd: RawFd,
    out_name_buf: Option<&mut [u8]>,
) -> Result<TaskFdQueryOutput<'buf>, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.task_fd_query.pid = pid;
    attr.task_fd_query.fd = target_fd as u32;
    let mut out_name_buf = out_name_buf;
    if let Some(buf) = &mut out_name_buf {
        attr.task_fd_query.buf = buf.as_mut_ptr() as u64;
        attr.task_fd_query.buf_len = buf.len() as u32;
    };

    if let Err((_, err)) = sys_bpf(bpf_cmd::BPF_TASK_FD_QUERY, &attr) {
        // The kernel here may leak an internal ENOTSUPP code (524), so
        // this needs to translate it back to POSIX-defined ENOTSUPP (95).
        return match err.raw_os_error() {
            Some(524) => Err(io::Error::from_raw_os_error(95)),
            _ => Err(err),
        };
    }

    let fd_type = unsafe { std::mem::transmute(attr.task_fd_query.fd_type) };
    let name = out_name_buf.map(|buf| unsafe {
        CStr::from_bytes_with_nul_unchecked(slice::from_raw_parts(
            buf.as_ptr(),
            attr.task_fd_query.buf_len as usize + 1,
        ))
    });
    let (probe_offset, probe_addr) = match fd_type {
        bpf_task_fd_type::BPF_FD_TYPE_KPROBE
        | bpf_task_fd_type::BPF_FD_TYPE_KRETPROBE
        | bpf_task_fd_type::BPF_FD_TYPE_UPROBE
        | bpf_task_fd_type::BPF_FD_TYPE_URETPROBE => unsafe {
            (
                Some(attr.task_fd_query.probe_offset),
                Some(attr.task_fd_query.probe_addr),
            )
        },
        _ => (None, None),
    };

    Ok(TaskFdQueryOutput {
        prog_id: unsafe { attr.task_fd_query.prog_id },
        fd_type,
        name,
        probe_offset,
        probe_addr,
    })
}

pub(crate) fn bpf_map_get_info_by_fd(prog_fd: RawFd) -> Result<bpf_map_info, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // info gets entirely populated by the kernel
    let info = MaybeUninit::zeroed();

    attr.info.bpf_fd = prog_fd as u32;
    attr.info.info = info.as_ptr() as *const _ as u64;
    attr.info.info_len = mem::size_of::<bpf_map_info>() as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &attr) {
        Ok(_) => Ok(unsafe { info.assume_init() }),
        Err((_, err)) => Err(err),
    }
}

pub(crate) fn bpf_link_get_info_by_fd(link_fd: RawFd) -> Result<bpf_link_info, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // info gets entirely populated by the kernel
    let info = unsafe { MaybeUninit::zeroed().assume_init() };

    attr.info.bpf_fd = link_fd as u32;
    attr.info.info = &info as *const _ as u64;
    attr.info.info_len = mem::size_of::<bpf_link_info>() as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &attr) {
        Ok(_) => Ok(info),
        Err((_, err)) => Err(err),
    }
}

pub(crate) fn btf_obj_get_info_by_fd(
    prog_fd: RawFd,
    buf: &mut [u8],
) -> Result<bpf_btf_info, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut info = unsafe { mem::zeroed::<bpf_btf_info>() };
    let buf_size = buf.len() as u32;
    info.btf = buf.as_ptr() as u64;
    info.btf_size = buf_size;
    attr.info.bpf_fd = prog_fd as u32;
    attr.info.info = &info as *const bpf_btf_info as u64;
    attr.info.info_len = mem::size_of::<bpf_btf_info>() as u32;

    match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &attr) {
        Ok(_) => Ok(info),
        Err((_, err)) => Err(err),
    }
}

pub(crate) fn bpf_raw_tracepoint_open(name: Option<&CStr>, prog_fd: RawFd) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.raw_tracepoint.name = match name {
        Some(n) => n.as_ptr() as u64,
        None => 0,
    };
    attr.raw_tracepoint.prog_fd = prog_fd as u32;

    sys_bpf(bpf_cmd::BPF_RAW_TRACEPOINT_OPEN, &attr)
}

pub(crate) fn bpf_load_btf(raw_btf: &[u8], log: &mut VerifierLog) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = raw_btf.as_ptr() as *const _ as u64;
    u.btf_size = mem::size_of_val(raw_btf) as u32;
    let log_buf = log.buf();
    if log_buf.capacity() > 0 {
        u.btf_log_level = 1;
        u.btf_log_buf = log_buf.as_mut_ptr() as u64;
        u.btf_log_size = log_buf.capacity() as u32;
    }
    sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr)
}

pub(crate) fn bpf_btf_get_fd_by_id(id: u32) -> Result<RawFd, io::Error> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;

    match sys_bpf(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &attr) {
        Ok(v) => Ok(v as RawFd),
        Err((_, err)) => Err(err),
    }
}

pub(crate) fn is_prog_name_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };
    let mut name: [c_char; 16] = [0; 16];
    let cstring = CString::new("aya_name_check").unwrap();
    let name_bytes = cstring.to_bytes();
    let len = min(name.len(), name_bytes.len());
    name[..len].copy_from_slice(unsafe {
        slice::from_raw_parts(name_bytes.as_ptr() as *const c_char, len)
    });
    u.prog_name = name;

    let prog: &[u8] = &[
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32;

    match sys_bpf(bpf_cmd::BPF_PROG_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int".to_string());
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    btf.add_type(int_type);
    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_func_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int".to_string());
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let a_name = btf.add_string("a".to_string());
    let b_name = btf.add_string("b".to_string());
    let params = vec![
        BtfParam {
            name_offset: a_name,
            btf_type: int_type_id,
        },
        BtfParam {
            name_offset: b_name,
            btf_type: int_type_id,
        },
    ];
    let func_proto = BtfType::FuncProto(FuncProto::new(params, int_type_id));
    let func_proto_type_id = btf.add_type(func_proto);

    let add = btf.add_string("inc".to_string());
    let func = BtfType::Func(Func::new(add, func_proto_type_id, FuncLinkage::Static));
    btf.add_type(func);

    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_func_global_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int".to_string());
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let a_name = btf.add_string("a".to_string());
    let b_name = btf.add_string("b".to_string());
    let params = vec![
        BtfParam {
            name_offset: a_name,
            btf_type: int_type_id,
        },
        BtfParam {
            name_offset: b_name,
            btf_type: int_type_id,
        },
    ];
    let func_proto = BtfType::FuncProto(FuncProto::new(params, int_type_id));
    let func_proto_type_id = btf.add_type(func_proto);

    let add = btf.add_string("inc".to_string());
    let func = BtfType::Func(Func::new(add, func_proto_type_id, FuncLinkage::Global));
    btf.add_type(func);

    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_datasec_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int".to_string());
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("foo".to_string());
    let var_type = BtfType::Var(Var::new(name_offset, int_type_id, VarLinkage::Static));
    let var_type_id = btf.add_type(var_type);

    let name_offset = btf.add_string(".data".to_string());
    let variables = vec![DataSecEntry {
        btf_type: var_type_id,
        offset: 0,
        size: 4,
    }];
    let datasec_type = BtfType::DataSec(DataSec::new(name_offset, variables, 4));
    btf.add_type(datasec_type);

    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_float_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("float".to_string());
    let float_type = BtfType::Float(Float::new(name_offset, 16));
    btf.add_type(float_type);

    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_decl_tag_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int".to_string());
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("foo".to_string());
    let var_type = BtfType::Var(Var::new(name_offset, int_type_id, VarLinkage::Static));
    let var_type_id = btf.add_type(var_type);

    let name_offset = btf.add_string("decl_tag".to_string());
    let decl_tag = BtfType::DeclTag(DeclTag::new(name_offset, var_type_id, -1));
    btf.add_type(decl_tag);

    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_btf_type_tag_supported() -> bool {
    let mut btf = Btf::new();

    let int_type = BtfType::Int(Int::new(0, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("int".to_string());
    let type_tag = BtfType::TypeTag(TypeTag::new(name_offset, int_type_id));
    let type_tag_type = btf.add_type(type_tag);

    btf.add_type(BtfType::Ptr(Ptr::new(0, type_tag_type)));

    let btf_bytes = btf.to_bytes();

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = btf_bytes.as_ptr() as u64;
    u.btf_size = btf_bytes.len() as u32;

    match sys_bpf(bpf_cmd::BPF_BTF_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub fn sys_bpf(cmd: bpf_cmd, attr: &bpf_attr) -> SysResult {
    syscall(Syscall::Bpf { cmd, attr })
}

pub(crate) fn retry_with_verifier_logs<F>(
    max_retries: usize,
    log: &mut VerifierLog,
    f: F,
) -> SysResult
where
    F: Fn(&mut VerifierLog) -> SysResult,
{
    // 1. Try the syscall
    let ret = f(log);
    if ret.is_ok() {
        return ret;
    }

    // 2. Grow the log buffer so we can capture verifier output
    //    Retry this up to max_retries times
    log.grow();
    let mut retries = 0;

    loop {
        let ret = f(log);
        match ret {
            Err((v, io_error)) if retries == 0 || io_error.raw_os_error() == Some(ENOSPC) => {
                if retries == max_retries {
                    return Err((v, io_error));
                }
                retries += 1;
                log.grow();
            }
            r => return r,
        }
    }
}
