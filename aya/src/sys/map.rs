use std::{
    cmp,
    ffi::CStr,
    mem::{self, MaybeUninit},
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd},
    slice,
};

use libc::ENOENT;

use super::utils::{fd_sys_bpf, iter_obj_ids, lookup, sys_bpf};
use crate::{
    generated::{bpf_attr, bpf_cmd, bpf_map_info, bpf_map_type},
    maps::PerCpuValues,
    obj,
    sys::{object::bpf_obj_get_info_by_fd, SysResult, SyscallError},
    util::KernelVersion,
    Pod, BPF_OBJ_NAME_LEN,
};

pub(crate) fn bpf_create_map(
    name: &CStr,
    def: &obj::Map,
    btf_fd: Option<BorrowedFd<'_>>,
    kernel_version: KernelVersion,
) -> SysResult<OwnedFd> {
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
                u.btf_fd = btf_fd.map(|fd| fd.as_raw_fd()).unwrap_or_default() as u32;
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

    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr) }
}

pub(crate) fn bpf_map_lookup_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
) -> SysResult<Option<V>> {
    lookup(fd, Some(key), flags, bpf_cmd::BPF_MAP_LOOKUP_ELEM)
}

pub(crate) fn bpf_map_lookup_elem_ptr<K: Pod, V>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: *mut V,
    flags: u64,
) -> SysResult<Option<()>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    match sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(_) => Ok(Some(())),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
) -> SysResult<Option<PerCpuValues<V>>> {
    let mut mem = PerCpuValues::<V>::alloc_kernel_mem().map_err(|io_error| (-1, io_error))?;
    match bpf_map_lookup_elem_ptr(fd, Some(key), mem.as_mut_ptr(), flags) {
        Ok(_) => Ok(Some(unsafe { PerCpuValues::from_kernel_mem(mem) })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_update_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: &V,
    flags: u64,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_update_elem_ptr<K, V>(
    fd: BorrowedFd<'_>,
    key: *const K,
    value: *mut V,
    flags: u64,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key as u64;
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_update_elem_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    values: &PerCpuValues<V>,
    flags: u64,
) -> SysResult<i64> {
    let mut mem = values.build_kernel_mem().map_err(|e| (-1, e))?;
    bpf_map_update_elem_ptr(fd, key, mem.as_mut_ptr(), flags)
}

pub(crate) fn bpf_map_push_elem<V: Pod>(
    fd: BorrowedFd<'_>,
    value: &V,
    flags: u64,
) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.__bindgen_anon_1.value = value as *const _ as u64;
    u.flags = flags;

    sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_delete_elem<K: Pod>(fd: BorrowedFd<'_>, key: &K) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key as *const _ as u64;

    sys_bpf(bpf_cmd::BPF_MAP_DELETE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_get_next_key<K: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
) -> SysResult<Option<K>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut next_key = MaybeUninit::uninit();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = key as *const _ as u64;
    }
    u.__bindgen_anon_1.next_key = &mut next_key as *mut _ as u64;

    match sys_bpf(bpf_cmd::BPF_MAP_GET_NEXT_KEY, &mut attr) {
        Ok(_) => Ok(Some(unsafe { next_key.assume_init() })),
        Err((_, io_error)) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn iter_map_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_MAP_GET_NEXT_ID, "bpf_map_get_next_id")
}

pub(crate) fn bpf_map_get_fd_by_id(map_id: u32) -> Result<OwnedFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.map_id = map_id;

    // SAFETY: BPF_MAP_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_GET_FD_BY_ID, &mut attr) }.map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        SyscallError {
            call: "bpf_map_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_map_get_info_by_fd(fd: BorrowedFd<'_>) -> Result<bpf_map_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |_| {})
}

pub(crate) fn bpf_map_lookup_and_delete_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    flags: u64,
) -> SysResult<Option<V>> {
    lookup(fd, key, flags, bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM)
}

// since kernel 5.2
pub(crate) fn bpf_map_freeze(fd: BorrowedFd<'_>) -> SysResult<i64> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    sys_bpf(bpf_cmd::BPF_MAP_FREEZE, &mut attr)
}
