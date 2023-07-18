use std::{
    cmp::{self, min},
    ffi::{CStr, CString},
    io,
    mem::{self, MaybeUninit},
    os::unix::io::RawFd,
    slice,
};

use crate::util::KernelVersion;
use libc::{c_char, c_long, close, ENOENT, ENOSPC};
use obj::{
    maps::{bpf_map_def, LegacyMap},
    BpfSectionKind,
};

use crate::{
    generated::{
        bpf_attach_type, bpf_attr, bpf_btf_info, bpf_cmd, bpf_insn, bpf_link_info, bpf_map_info,
        bpf_map_type, bpf_prog_info, bpf_prog_type, BPF_F_REPLACE,
    },
    maps::{MapData, PerCpuValues},
    obj::{
        self,
        btf::{
            BtfParam, BtfType, DataSec, DataSecEntry, DeclTag, Float, Func, FuncLinkage, FuncProto,
            FuncSecInfo, Int, IntEncoding, LineSecInfo, Ptr, TypeTag, Var, VarLinkage,
        },
        copy_instructions,
    },
    sys::{syscall, SysResult, Syscall},
    Btf, Pod, VerifierLogLevel, BPF_OBJ_NAME_LEN,
};

pub(crate) fn bpf_create_map(
    name: &CStr,
    def: &obj::Map,
    btf_fd: Option<RawFd>,
    kernel_version: KernelVersion,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = def.map_type();
    u.key_size = def.key_size();
    u.value_size = def.value_size();
    u.max_entries = def.max_entries();
    u.map_flags = def.map_flags();

    if let obj::Map::Btf(m) = def {
        use bpf_map_type::*;

        // Mimic https://github.com/libbpf/libbpf/issues/355
        // Currently a bunch of (usually pretty specialized) BPF maps do not support
        // specifying BTF types for the key and value.
        match u.map_type.try_into() {
            Ok(BPF_MAP_TYPE_PERF_EVENT_ARRAY)
            | Ok(BPF_MAP_TYPE_CGROUP_ARRAY)
            | Ok(BPF_MAP_TYPE_STACK_TRACE)
            | Ok(BPF_MAP_TYPE_ARRAY_OF_MAPS)
            | Ok(BPF_MAP_TYPE_HASH_OF_MAPS)
            | Ok(BPF_MAP_TYPE_DEVMAP)
            | Ok(BPF_MAP_TYPE_DEVMAP_HASH)
            | Ok(BPF_MAP_TYPE_CPUMAP)
            | Ok(BPF_MAP_TYPE_XSKMAP)
            | Ok(BPF_MAP_TYPE_SOCKMAP)
            | Ok(BPF_MAP_TYPE_SOCKHASH)
            | Ok(BPF_MAP_TYPE_QUEUE)
            | Ok(BPF_MAP_TYPE_STACK)
            | Ok(BPF_MAP_TYPE_RINGBUF) => {
                u.btf_key_type_id = 0;
                u.btf_value_type_id = 0;
                u.btf_fd = 0;
            }
            _ => {
                u.btf_key_type_id = m.def.btf_key_type_id;
                u.btf_value_type_id = m.def.btf_value_type_id;
                u.btf_fd = btf_fd.unwrap_or_default() as u32;
            }
        }
    }

    // https://github.com/torvalds/linux/commit/ad5b177bd73f5107d97c36f56395c4281fb6f089
    // The map name was added as a parameter in kernel 4.15+ so we skip adding it on
    // older kernels for compatibility
    if kernel_version >= KernelVersion::new(4, 15, 0) {
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
    pub(crate) flags: u32,
}

pub(crate) fn bpf_load_program(
    aya_attr: &BpfLoadProgramAttrs,
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
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
    if !log_buf.is_empty() {
        u.log_level = verifier_log_level.bits();
        u.log_buf = log_buf.as_mut_ptr() as u64;
        u.log_size = log_buf.len() as u32;
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

    attr.link_create.__bindgen_anon_1.prog_fd = prog_fd as u32;
    attr.link_create.__bindgen_anon_2.target_fd = target_fd as u32;
    attr.link_create.attach_type = attach_type as u32;
    attr.link_create.flags = flags;
    if let Some(btf_id) = btf_id {
        attr.link_create.__bindgen_anon_3.target_btf_id = btf_id;
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
    attr.link_update.__bindgen_anon_1.new_prog_fd = new_prog_fd as u32;
    if let Some(fd) = old_prog_fd {
        attr.link_update.__bindgen_anon_2.old_prog_fd = fd as u32;
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
    buf: &[u8],
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

pub(crate) fn bpf_load_btf(
    raw_btf: &[u8],
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
) -> SysResult {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = raw_btf.as_ptr() as *const _ as u64;
    u.btf_size = mem::size_of_val(raw_btf) as u32;
    if !log_buf.is_empty() {
        u.btf_log_level = verifier_log_level.bits();
        u.btf_log_buf = log_buf.as_mut_ptr() as u64;
        u.btf_log_size = log_buf.len() as u32;
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

pub(crate) fn is_probe_read_kernel_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0xbf, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = r10
        0x07, 0x01, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, // r1 -= 8
        0xb7, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // r2 = 8
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r3 = 0
        0x85, 0x00, 0x00, 0x00, 0x71, 0x00, 0x00, 0x00, // call 113
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT as u32;

    match sys_bpf(bpf_cmd::BPF_PROG_LOAD, &attr) {
        Ok(v) => {
            let fd = v as RawFd;
            unsafe { close(fd) };
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn is_perf_link_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT as u32;

    if let Ok(fd) = sys_bpf(bpf_cmd::BPF_PROG_LOAD, &attr) {
        if let Err((_, e)) =
            // Uses an invalid target FD so we get EBADF if supported.
            bpf_link_create(fd as i32, -1, bpf_attach_type::BPF_PERF_EVENT, None, 0)
        {
            // Returns EINVAL if unsupported. EBADF if supported.
            let res = e.raw_os_error() == Some(libc::EBADF);
            unsafe { libc::close(fd as i32) };
            return res;
        }
    }
    false
}

pub(crate) fn is_bpf_global_data_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0x18, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ld_pseudo r1, 0x2, 0x0
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, //
        0x7a, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // stdw [r1 + 0x0], 0x2a
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let mut insns = copy_instructions(prog).unwrap();

    let mut map_data = MapData {
        obj: obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                key_size: 4,
                value_size: 32,
                max_entries: 1,
                ..Default::default()
            },
            section_index: 0,
            section_kind: BpfSectionKind::Maps,
            symbol_index: None,
            data: Vec::new(),
        }),
        fd: None,
        pinned: false,
        btf_fd: None,
    };

    if let Ok(map_fd) = map_data.create("aya_global") {
        insns[0].imm = map_fd;

        let gpl = b"GPL\0";
        u.license = gpl.as_ptr() as u64;
        u.insn_cnt = insns.len() as u32;
        u.insns = insns.as_ptr() as u64;
        u.prog_type = bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32;

        if let Ok(v) = sys_bpf(bpf_cmd::BPF_PROG_LOAD, &attr) {
            let fd = v as RawFd;

            unsafe { close(fd) };

            return true;
        }
    }

    false
}

pub(crate) fn is_bpf_cookie_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let prog: &[u8] = &[
        0x85, 0x00, 0x00, 0x00, 0xae, 0x00, 0x00, 0x00, // call bpf_get_attach_cookie
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    let insns = copy_instructions(prog).unwrap();
    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_KPROBE as u32;

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
    let name_offset = btf.add_string("int");
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
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let a_name = btf.add_string("a");
    let b_name = btf.add_string("b");
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

    let add = btf.add_string("inc");
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
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let a_name = btf.add_string("a");
    let b_name = btf.add_string("b");
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

    let add = btf.add_string("inc");
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
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("foo");
    let var_type = BtfType::Var(Var::new(name_offset, int_type_id, VarLinkage::Static));
    let var_type_id = btf.add_type(var_type);

    let name_offset = btf.add_string(".data");
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
    let name_offset = btf.add_string("float");
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
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    let int_type_id = btf.add_type(int_type);

    let name_offset = btf.add_string("foo");
    let var_type = BtfType::Var(Var::new(name_offset, int_type_id, VarLinkage::Static));
    let var_type_id = btf.add_type(var_type);

    let name_offset = btf.add_string("decl_tag");
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

    let name_offset = btf.add_string("int");
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

pub(crate) fn bpf_prog_get_next_id(id: u32) -> Result<Option<u32>, (c_long, io::Error)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_6 };
    u.__bindgen_anon_1.start_id = id;
    match sys_bpf(bpf_cmd::BPF_PROG_GET_NEXT_ID, &attr) {
        Ok(_) => Ok(Some(unsafe { attr.__bindgen_anon_6.next_id })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn retry_with_verifier_logs(
    max_retries: usize,
    f: impl Fn(&mut [u8]) -> SysResult,
) -> (SysResult, String) {
    const MIN_LOG_BUF_SIZE: usize = 1024 * 10;
    const MAX_LOG_BUF_SIZE: usize = (std::u32::MAX >> 8) as usize;

    let mut log_buf = Vec::new();
    let mut retries = 0;
    loop {
        let ret = f(log_buf.as_mut_slice());
        if retries != max_retries {
            if let Err((_, io_error)) = &ret {
                if retries == 0 || io_error.raw_os_error() == Some(ENOSPC) {
                    let len = (log_buf.capacity() * 10).clamp(MIN_LOG_BUF_SIZE, MAX_LOG_BUF_SIZE);
                    log_buf.resize(len, 0);
                    if let Some(first) = log_buf.first_mut() {
                        *first = 0;
                    }
                    retries += 1;
                    continue;
                }
            }
        }
        if let Some(pos) = log_buf.iter().position(|b| *b == 0) {
            log_buf.truncate(pos);
        }
        let log_buf = String::from_utf8(log_buf).unwrap();

        break (ret, log_buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::override_syscall;
    use libc::{EBADF, EINVAL};

    #[test]
    fn test_perf_link_supported() {
        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Err((-1, io::Error::from_raw_os_error(EBADF))),
            _ => Ok(42),
        });
        let supported = is_perf_link_supported();
        assert!(supported);

        override_syscall(|call| match call {
            Syscall::Bpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Err((-1, io::Error::from_raw_os_error(EINVAL))),
            _ => Ok(42),
        });
        let supported = is_perf_link_supported();
        assert!(!supported);
    }
}
