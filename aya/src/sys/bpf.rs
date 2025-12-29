use std::{
    cmp,
    ffi::{CStr, CString, c_char},
    fmt, io, iter,
    mem::{self, MaybeUninit},
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, RawFd},
    ptr,
};

use assert_matches::assert_matches;
use aya_obj::{
    EbpfSectionKind, VerifierLog,
    btf::{
        BtfEnum64, BtfParam, BtfType, DataSec, DataSecEntry, DeclTag, Enum64, Float, Func,
        FuncLinkage, FuncProto, FuncSecInfo, Int, IntEncoding, LineSecInfo, Ptr, TypeTag, Var,
        VarLinkage,
    },
    generated::{
        BPF_ADD, BPF_ALU64, BPF_CALL, BPF_DW, BPF_EXIT, BPF_F_REPLACE, BPF_IMM, BPF_JMP, BPF_K,
        BPF_LD, BPF_MEM, BPF_MOV, BPF_PSEUDO_MAP_VALUE, BPF_ST, BPF_X, bpf_attach_type, bpf_attr,
        bpf_btf_info, bpf_cmd, bpf_func_id::*, bpf_insn, bpf_link_info, bpf_map_info, bpf_map_type,
        bpf_prog_info, bpf_prog_type, bpf_stats_type,
    },
    maps::{LegacyMap, bpf_map_def},
};
use libc::{
    EBADF, ENOENT, ENOSPC, EPERM, RLIM_INFINITY, RLIMIT_MEMLOCK, getrlimit, rlim_t, rlimit,
    setrlimit,
};
use log::warn;

use crate::{
    Btf, Pod, VerifierLogLevel,
    maps::{MapData, PerCpuValues},
    programs::{LsmAttachType, ProgramType, links::LinkRef},
    sys::{Syscall, SyscallError, syscall},
    util::KernelVersion,
};

pub(crate) fn bpf_create_iter(link_fd: BorrowedFd<'_>) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.iter_create };
    u.link_fd = link_fd.as_raw_fd() as u32;

    // SAFETY: BPF_ITER_CREATE returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_ITER_CREATE, &mut attr) }
}

pub(crate) fn bpf_create_map(
    name: &CStr,
    def: &aya_obj::Map,
    btf_fd: Option<BorrowedFd<'_>>,
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = def.map_type();
    u.key_size = def.key_size();
    u.value_size = def.value_size();
    u.max_entries = def.max_entries();
    u.map_flags = def.map_flags();

    if let aya_obj::Map::Btf(m) = def {
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
    if KernelVersion::at_least(4, 15, 0) {
        let name_bytes = name.to_bytes();
        let len = cmp::min(name_bytes.len(), u.map_name.len() - 1); // Ensure NULL termination.
        u.map_name[..len]
            .copy_from_slice(unsafe { mem::transmute::<&[u8], &[c_char]>(&name_bytes[..len]) });
    }

    bpf_map_create(&mut attr)
}

pub(crate) fn bpf_pin_object(fd: BorrowedFd<'_>, path: &CStr) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.bpf_fd = fd.as_raw_fd() as u32;
    u.pathname = path.as_ptr() as u64;
    unit_sys_bpf(bpf_cmd::BPF_OBJ_PIN, &mut attr)
}

/// Introduced in kernel v4.4.
pub(crate) fn bpf_get_object(path: &CStr) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_4 };
    u.pathname = path.as_ptr() as u64;
    // SAFETY: BPF_OBJ_GET returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_OBJ_GET, &mut attr) }
}

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
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_3 };

    if let Some(name) = &aya_attr.name {
        let name_bytes = name.to_bytes();
        let len = cmp::min(name_bytes.len(), u.prog_name.len() - 1); // Ensure NULL termination.
        u.prog_name[..len]
            .copy_from_slice(unsafe { mem::transmute::<&[u8], &[c_char]>(&name_bytes[..len]) });
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
            u.line_info = line_info_buf.as_ptr() as u64;
            u.line_info_cnt = aya_attr.line_info.len() as u32;
            u.line_info_rec_size = aya_attr.line_info_rec_size as u32;
        }
        if aya_attr.func_info_rec_size > 0 {
            u.func_info = func_info_buf.as_ptr() as u64;
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
        u.__bindgen_anon_1.attach_btf_obj_fd = v.as_raw_fd() as u32;
    }
    if let Some(v) = aya_attr.attach_prog_fd {
        u.__bindgen_anon_1.attach_prog_fd = v.as_raw_fd() as u32;
    }

    if let Some(v) = aya_attr.attach_btf_id {
        u.attach_btf_id = v;
    }
    bpf_prog_load(&mut attr)
}

fn lookup<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    flags: u64,
    cmd: bpf_cmd,
) -> io::Result<Option<V>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut value = MaybeUninit::zeroed();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = ptr::from_ref(key) as u64;
    }
    u.__bindgen_anon_1.value = ptr::from_mut(&mut value) as u64;
    u.flags = flags;

    match unit_sys_bpf(cmd, &mut attr) {
        Ok(()) => Ok(Some(unsafe { value.assume_init() })),
        Err(io_error) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_lookup_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
) -> io::Result<Option<V>> {
    lookup(fd, Some(key), flags, bpf_cmd::BPF_MAP_LOOKUP_ELEM)
}

pub(crate) fn bpf_map_lookup_and_delete_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    flags: u64,
) -> io::Result<Option<V>> {
    lookup(fd, key, flags, bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM)
}

pub(crate) fn bpf_map_lookup_elem_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
) -> io::Result<Option<PerCpuValues<V>>> {
    let mut mem = PerCpuValues::<V>::alloc_kernel_mem()?;
    match bpf_map_lookup_elem_ptr(fd, Some(key), mem.as_mut_ptr(), flags) {
        Ok(v) => Ok(v.map(|()| unsafe { PerCpuValues::from_kernel_mem(mem) })),
        Err(io_error) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Batch lookup and delete elements from a per-cpu map.
///
/// # Arguments
///
/// * `fd` - The file descriptor of the map
/// * `in_batch` - Optional reference to the previous batch cursor (None for first call)
/// * `batch_size` - Maximum number of elements to retrieve
/// * `flags` - Operation flags
///
/// # Returns
///
/// Returns a tuple of (keys, values, out_batch) where:
/// - keys: Vector of retrieved keys
/// - values: Vector of retrieved per-CPU values
/// - out_batch: Optional cursor for the next batch
///
/// # Introduced in kernel v5.6
type PerCpuBatchResult<K, V> = io::Result<(Vec<K>, Vec<PerCpuValues<V>>, Option<K>)>;

pub(crate) fn bpf_map_lookup_and_delete_batch_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    in_batch: Option<&K>,
    batch_size: usize,
    flags: u64,
) -> PerCpuBatchResult<K, V> {
    if batch_size == 0 {
        return Ok((Vec::new(), Vec::new(), None));
    }

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut out_batch = MaybeUninit::<K>::uninit();
    let mut keys = vec![unsafe { mem::zeroed() }; batch_size];

    let value_size = (mem::size_of::<V>() + 7) & !7;
    let nr_cpus = crate::util::nr_cpus().map_err(|(_, error)| error)?;
    // value out buffer
    let mut values_buffer = vec![0u8; batch_size * nr_cpus * value_size];

    let batch_attr = unsafe { &mut attr.batch };
    batch_attr.map_fd = fd.as_raw_fd() as u32;
    batch_attr.keys = keys.as_mut_ptr() as u64;
    batch_attr.values = values_buffer.as_mut_ptr() as u64;
    batch_attr.count = batch_size as u32;
    if let Some(batch) = in_batch {
        batch_attr.in_batch = ptr::from_ref(batch) as u64;
    }
    batch_attr.out_batch = ptr::from_mut(&mut out_batch) as u64;
    batch_attr.flags = flags;

    if let Err(e) = unit_sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH, &mut attr) {
        if e.raw_os_error() != Some(ENOENT) {
            return Err(e);
        }
    }

    let actual_count = unsafe { attr.batch.count } as usize;
    keys.truncate(actual_count);
    let mut values = Vec::with_capacity(actual_count);
    for i in 0..actual_count {
        let offset = i * nr_cpus * value_size;
        let per_cpu_values: Vec<V> = (0..nr_cpus)
            .map(|cpu| {
                let value_offset = offset + cpu * value_size;
                // SAFETY:
                // 1. `values_buffer` is allocated with size `batch_size * nr_cpus * value_size`.
                // 2. The loop bounds ensure `i < actual_count` (<= batch_size) and `cpu < nr_cpus`.
                // 3. Therefore, `value_offset` is always within the bounds of `values_buffer`.
                // 4. `ptr::read_unaligned` allows reading potentially unaligned values from the byte buffer.
                unsafe { ptr::read_unaligned(values_buffer.as_ptr().add(value_offset).cast::<V>()) }
            })
            .collect();

        values.push(PerCpuValues::try_from(per_cpu_values).map_err(io::Error::other)?);
    }
    let out_batch = if actual_count > 0 {
        Some(unsafe { out_batch.assume_init() })
    } else {
        None
    };
    Ok((keys, values, out_batch))
}

pub(crate) fn bpf_map_lookup_elem_ptr<K: Pod, V>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: *mut V,
    flags: u64,
) -> io::Result<Option<()>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = ptr::from_ref(key) as u64;
    }
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    match unit_sys_bpf(bpf_cmd::BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(()) => Ok(Some(())),
        Err(io_error) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn bpf_map_update_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    value: &V,
    flags: u64,
) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = ptr::from_ref(key) as u64;
    }
    u.__bindgen_anon_1.value = ptr::from_ref(value) as u64;
    u.flags = flags;

    unit_sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_push_elem<V: Pod>(
    fd: BorrowedFd<'_>,
    value: &V,
    flags: u64,
) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.__bindgen_anon_1.value = ptr::from_ref(value) as u64;
    u.flags = flags;

    unit_sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_update_elem_ptr<K, V>(
    fd: BorrowedFd<'_>,
    key: *const K,
    value: *mut V,
    flags: u64,
) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = key as u64;
    u.__bindgen_anon_1.value = value as u64;
    u.flags = flags;

    unit_sys_bpf(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_update_elem_per_cpu<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    values: &PerCpuValues<V>,
    flags: u64,
) -> io::Result<()> {
    let mut mem = values.build_kernel_mem()?;
    bpf_map_update_elem_ptr(fd, key, mem.as_mut_ptr(), flags)
}

pub(crate) fn bpf_map_delete_elem<K: Pod>(fd: BorrowedFd<'_>, key: &K) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    u.key = ptr::from_ref(key) as u64;

    unit_sys_bpf(bpf_cmd::BPF_MAP_DELETE_ELEM, &mut attr)
}

pub(crate) fn bpf_map_get_next_key<K: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
) -> io::Result<Option<K>> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut next_key = MaybeUninit::uninit();

    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    if let Some(key) = key {
        u.key = ptr::from_ref(key) as u64;
    }
    u.__bindgen_anon_1.next_key = ptr::from_mut(&mut next_key) as u64;

    match unit_sys_bpf(bpf_cmd::BPF_MAP_GET_NEXT_KEY, &mut attr) {
        Ok(()) => Ok(Some(unsafe { next_key.assume_init() })),
        Err(io_error) if io_error.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

// since kernel 5.2
pub(crate) fn bpf_map_freeze(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_2 };
    u.map_fd = fd.as_raw_fd() as u32;
    unit_sys_bpf(bpf_cmd::BPF_MAP_FREEZE, &mut attr)
}

pub(crate) enum LinkTarget<'f> {
    Fd(BorrowedFd<'f>),
    IfIndex(u32),
    Iter,
}

// Models https://github.com/torvalds/linux/blob/2144da25/include/uapi/linux/bpf.h#L1724-L1782.
pub(crate) enum BpfLinkCreateArgs<'a> {
    TargetBtfId(u32),
    // since kernel 5.15
    PerfEvent { bpf_cookie: u64 },
    // since kernel 6.6
    Tcx(&'a LinkRef),
}

// since kernel 5.7
pub(crate) fn bpf_link_create(
    prog_fd: BorrowedFd<'_>,
    target: LinkTarget<'_>,
    attach_type: bpf_attach_type,
    flags: u32,
    args: Option<BpfLinkCreateArgs<'_>>,
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_create.__bindgen_anon_1.prog_fd = prog_fd.as_raw_fd() as u32;

    match target {
        LinkTarget::Fd(fd) => {
            attr.link_create.__bindgen_anon_2.target_fd = fd.as_raw_fd() as u32;
        }
        LinkTarget::IfIndex(ifindex) => {
            attr.link_create.__bindgen_anon_2.target_ifindex = ifindex;
        }
        // When attaching to an iterator program, no target FD is needed. In
        // fact, the kernel explicitly rejects non-zero target FDs for
        // iterators:
        // https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/bpf_iter.c#L517-L518
        LinkTarget::Iter => {}
    };
    attr.link_create.attach_type = attach_type as u32;
    attr.link_create.flags = flags;

    if let Some(args) = args {
        match args {
            BpfLinkCreateArgs::TargetBtfId(btf_id) => {
                attr.link_create.__bindgen_anon_3.target_btf_id = btf_id;
            }
            BpfLinkCreateArgs::PerfEvent { bpf_cookie } => {
                attr.link_create.__bindgen_anon_3.perf_event.bpf_cookie = bpf_cookie;
            }
            BpfLinkCreateArgs::Tcx(link_ref) => match link_ref {
                LinkRef::Fd(fd) => {
                    attr.link_create
                        .__bindgen_anon_3
                        .tcx
                        .__bindgen_anon_1
                        .relative_fd = fd.to_owned() as u32;
                }
                LinkRef::Id(id) => {
                    attr.link_create
                        .__bindgen_anon_3
                        .tcx
                        .__bindgen_anon_1
                        .relative_id = id.to_owned();
                }
            },
        }
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
) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.link_update.link_fd = link_fd.as_raw_fd() as u32;
    attr.link_update.__bindgen_anon_1.new_prog_fd = new_prog_fd.as_raw_fd() as u32;
    if let Some(fd) = old_prog_fd {
        attr.link_update.__bindgen_anon_2.old_prog_fd = fd as u32;
        attr.link_update.flags = flags | BPF_F_REPLACE;
    } else {
        attr.link_update.flags = flags;
    }

    unit_sys_bpf(bpf_cmd::BPF_LINK_UPDATE, &mut attr)
}

pub(crate) fn bpf_prog_attach(
    prog_fd: BorrowedFd<'_>,
    target_fd: BorrowedFd<'_>,
    attach_type: bpf_attach_type,
    flags: u32,
) -> Result<(), SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_5.attach_bpf_fd = prog_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = target_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;
    attr.__bindgen_anon_5.attach_flags = flags;

    unit_sys_bpf(bpf_cmd::BPF_PROG_ATTACH, &mut attr).map_err(|io_error| SyscallError {
        call: "bpf_prog_attach",
        io_error,
    })
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

    unit_sys_bpf(bpf_cmd::BPF_PROG_DETACH, &mut attr).map_err(|io_error| SyscallError {
        call: "bpf_prog_detach",
        io_error,
    })
}

#[derive(Debug)]
pub(crate) enum ProgQueryTarget<'a> {
    Fd(BorrowedFd<'a>),
    IfIndex(u32),
}

pub(crate) fn bpf_prog_query(
    target: &ProgQueryTarget<'_>,
    attach_type: bpf_attach_type,
    query_flags: u32,
    attach_flags: Option<&mut u32>,
    prog_ids: &mut [u32],
    prog_cnt: &mut u32,
    revision: &mut u64,
) -> io::Result<()> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    match target {
        ProgQueryTarget::Fd(fd) => {
            attr.query.__bindgen_anon_1.target_fd = fd.as_raw_fd() as u32;
        }
        ProgQueryTarget::IfIndex(ifindex) => {
            attr.query.__bindgen_anon_1.target_ifindex = *ifindex;
        }
    }
    attr.query.attach_type = attach_type as u32;
    attr.query.query_flags = query_flags;
    attr.query.__bindgen_anon_2.prog_cnt = prog_ids.len() as u32;
    attr.query.prog_ids = prog_ids.as_mut_ptr() as u64;
    let ret = unit_sys_bpf(bpf_cmd::BPF_PROG_QUERY, &mut attr);

    *prog_cnt = unsafe { attr.query.__bindgen_anon_2.prog_cnt };
    *revision = unsafe { attr.query.revision };

    if let Some(attach_flags) = attach_flags {
        *attach_flags = unsafe { attr.query.attach_flags };
    }

    ret
}

/// Introduced in kernel v4.13.
pub(crate) fn bpf_prog_get_fd_by_id(prog_id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = prog_id;
    // SAFETY: BPF_PROG_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &mut attr) }.map_err(|io_error| {
        SyscallError {
            call: "bpf_prog_get_fd_by_id",
            io_error,
        }
    })
}

/// Introduced in kernel v4.13.
fn bpf_obj_get_info_by_fd<T, F: FnOnce(&mut T)>(
    fd: BorrowedFd<'_>,
    init: F,
) -> Result<T, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let mut info = unsafe { mem::zeroed() };

    init(&mut info);

    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info = ptr::from_ref(&info) as u64;
    attr.info.info_len = mem::size_of_val(&info) as u32;

    match unit_sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
        Ok(()) => Ok(info),
        Err(io_error) => Err(SyscallError {
            call: "bpf_obj_get_info_by_fd",
            io_error,
        }),
    }
}

/// Introduced in kernel v4.13.
pub(crate) fn bpf_prog_get_info_by_fd(
    fd: BorrowedFd<'_>,
    map_ids: &mut [u32],
) -> Result<bpf_prog_info, SyscallError> {
    // An `E2BIG` error can occur on kernels below v4.15 when handing over a large struct where the
    // extra space is not all-zero bytes.
    bpf_obj_get_info_by_fd(fd, |info: &mut bpf_prog_info| {
        if !map_ids.is_empty() {
            info.nr_map_ids = map_ids.len() as u32;
            info.map_ids = map_ids.as_mut_ptr() as u64;
        }
    })
}

/// Introduced in kernel v4.13.
pub(crate) fn bpf_map_get_fd_by_id(map_id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.map_id = map_id;

    // SAFETY: BPF_MAP_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_GET_FD_BY_ID, &mut attr) }.map_err(|io_error| {
        SyscallError {
            call: "bpf_map_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_map_get_info_by_fd(fd: BorrowedFd<'_>) -> Result<bpf_map_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |_| {})
}

pub(crate) fn bpf_link_get_fd_by_id(link_id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.link_id = link_id;
    // SAFETY: BPF_LINK_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_LINK_GET_FD_BY_ID, &mut attr) }.map_err(|io_error| {
        SyscallError {
            call: "bpf_link_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn bpf_link_get_info_by_fd(fd: BorrowedFd<'_>) -> Result<bpf_link_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |_| {})
}

pub(crate) fn btf_obj_get_info_by_fd(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
) -> Result<bpf_btf_info, SyscallError> {
    bpf_obj_get_info_by_fd(fd, |info: &mut bpf_btf_info| {
        info.btf = buf.as_mut_ptr() as u64;
        info.btf_size = buf.len() as u32;
    })
}

pub(crate) fn bpf_raw_tracepoint_open(
    name: Option<&CStr>,
    prog_fd: BorrowedFd<'_>,
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };

    attr.raw_tracepoint.name = match name {
        Some(n) => n.as_ptr() as u64,
        None => 0,
    };
    attr.raw_tracepoint.prog_fd = prog_fd.as_raw_fd() as u32;

    // SAFETY: BPF_RAW_TRACEPOINT_OPEN returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_RAW_TRACEPOINT_OPEN, &mut attr) }
}

pub(crate) fn bpf_load_btf(
    raw_btf: &[u8],
    log_buf: &mut [u8],
    verifier_log_level: VerifierLogLevel,
) -> io::Result<crate::MockableFd> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_7 };
    u.btf = raw_btf.as_ptr() as u64;
    u.btf_size = mem::size_of_val(raw_btf) as u32;
    if !log_buf.is_empty() {
        u.btf_log_level = verifier_log_level.bits();
        u.btf_log_buf = log_buf.as_mut_ptr() as u64;
        u.btf_log_size = log_buf.len() as u32;
    }
    // SAFETY: `BPF_BTF_LOAD` returns a newly created fd.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_BTF_LOAD, &mut attr) }
}

// SAFETY: only use for bpf_cmd that return a new file descriptor on success.
pub(super) unsafe fn fd_sys_bpf(
    cmd: bpf_cmd,
    attr: &mut bpf_attr,
) -> io::Result<crate::MockableFd> {
    let fd = sys_bpf(cmd, attr)?;
    let fd = fd.try_into().map_err(|std::num::TryFromIntError { .. }| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{cmd:?}: invalid fd returned: {fd}"),
        )
    })?;
    Ok(unsafe { crate::MockableFd::from_raw_fd(fd) })
}

static RAISE_MEMLIMIT: std::sync::Once = std::sync::Once::new();
fn with_raised_rlimit_retry<T, F: FnMut() -> io::Result<T>>(mut op: F) -> io::Result<T> {
    let mut result = op();
    if matches!(result.as_ref(), Err(err) if err.raw_os_error() == Some(EPERM)) {
        RAISE_MEMLIMIT.call_once(|| {
            if KernelVersion::at_least(5, 11, 0) {
                return;
            }
            let mut limit = mem::MaybeUninit::<rlimit>::uninit();
            let ret = unsafe { getrlimit(RLIMIT_MEMLOCK, limit.as_mut_ptr()) };
            if ret != 0 {
                warn!("getrlimit(RLIMIT_MEMLOCK) failed: {ret}");
                return;
            }
            let rlimit {
                rlim_cur,
                rlim_max: _,
            } = unsafe { limit.assume_init() };

            if rlim_cur == RLIM_INFINITY {
                return;
            }
            let limit = rlimit {
                rlim_cur: RLIM_INFINITY,
                rlim_max: RLIM_INFINITY,
            };
            let ret = unsafe { setrlimit(RLIMIT_MEMLOCK, &limit) };
            if ret != 0 {
                struct HumanSize(rlim_t);

                impl fmt::Display for HumanSize {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        let &Self(size) = self;
                        if size < 1024 {
                            write!(f, "{size} bytes")
                        } else if size < 1024 * 1024 {
                            write!(f, "{} KiB", size / 1024)
                        } else {
                            write!(f, "{} MiB", size / 1024 / 1024)
                        }
                    }
                }
                warn!(
                    "setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY) failed: {ret}; current value is {}",
                    HumanSize(rlim_cur)
                );
            }
        });
        // Retry after raising the limit.
        result = op();
    }
    result
}

pub(super) fn bpf_map_create(attr: &mut bpf_attr) -> io::Result<crate::MockableFd> {
    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    with_raised_rlimit_retry(|| unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, attr) })
}

pub(crate) fn bpf_btf_get_fd_by_id(id: u32) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;

    // SAFETY: BPF_BTF_GET_FD_BY_ID returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &mut attr) }.map_err(|io_error| {
        SyscallError {
            call: "bpf_btf_get_fd_by_id",
            io_error,
        }
    })
}

pub(crate) fn is_prog_name_supported() -> bool {
    with_trivial_prog(ProgramType::TracePoint, |attr| {
        let u = unsafe { &mut attr.__bindgen_anon_3 };
        let name = c"aya_name_check";
        let name_bytes = name.to_bytes();
        let len = cmp::min(name_bytes.len(), u.prog_name.len() - 1); // Ensure NULL termination.
        u.prog_name[..len]
            .copy_from_slice(unsafe { mem::transmute::<&[u8], &[c_char]>(&name_bytes[..len]) });
        bpf_prog_load(attr).is_ok()
    })
}

fn new_insn(code: u8, dst_reg: u8, src_reg: u8, offset: i16, imm: i32) -> bpf_insn {
    let mut insn = unsafe { mem::zeroed::<bpf_insn>() };
    insn.code = code;
    insn.set_dst_reg(dst_reg);
    insn.set_src_reg(src_reg);
    insn.off = offset;
    insn.imm = imm;
    insn
}

pub(super) fn with_trivial_prog<T, F>(program_type: ProgramType, op: F) -> T
where
    F: FnOnce(&mut bpf_attr) -> T,
{
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let mov64_imm = (BPF_ALU64 | BPF_MOV | BPF_K) as u8;
    let exit = (BPF_JMP | BPF_EXIT) as u8;
    let insns = [new_insn(mov64_imm, 0, 0, 0, 0), new_insn(exit, 0, 0, 0, 0)];

    let gpl = c"GPL";
    u.license = gpl.as_ptr() as u64;

    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;

    // `expected_attach_type` field was added in v4.17 https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/bpf.h#L310.
    let expected_attach_type = match program_type {
        ProgramType::SkMsg => Some(bpf_attach_type::BPF_SK_MSG_VERDICT),
        ProgramType::CgroupSockAddr => Some(bpf_attach_type::BPF_CGROUP_INET4_BIND),
        ProgramType::LircMode2 => Some(bpf_attach_type::BPF_LIRC_MODE2),
        ProgramType::SkReuseport => Some(bpf_attach_type::BPF_SK_REUSEPORT_SELECT),
        ProgramType::FlowDissector => Some(bpf_attach_type::BPF_FLOW_DISSECTOR),
        ProgramType::CgroupSysctl => Some(bpf_attach_type::BPF_CGROUP_SYSCTL),
        ProgramType::CgroupSockopt => Some(bpf_attach_type::BPF_CGROUP_GETSOCKOPT),
        ProgramType::Tracing => Some(bpf_attach_type::BPF_TRACE_FENTRY),
        ProgramType::Lsm(lsm_attach_type) => match lsm_attach_type {
            LsmAttachType::Mac => Some(bpf_attach_type::BPF_LSM_MAC),
            LsmAttachType::Cgroup => Some(bpf_attach_type::BPF_LSM_CGROUP),
        },
        ProgramType::SkLookup => Some(bpf_attach_type::BPF_SK_LOOKUP),
        ProgramType::Netfilter => Some(bpf_attach_type::BPF_NETFILTER),
        // Program types below v4.17, or do not accept `expected_attach_type`, should leave the
        // field unset.
        //
        // Types below v4.17:
        ProgramType::Unspecified
        | ProgramType::SocketFilter
        | ProgramType::KProbe
        | ProgramType::SchedClassifier
        | ProgramType::SchedAction
        | ProgramType::TracePoint
        | ProgramType::Xdp
        | ProgramType::PerfEvent
        | ProgramType::CgroupSkb
        | ProgramType::CgroupSock
        | ProgramType::LwtInput
        | ProgramType::LwtOutput
        | ProgramType::LwtXmit
        | ProgramType::SockOps
        | ProgramType::SkSkb
        | ProgramType::CgroupDevice
        // Types that do not accept `expected_attach_type`:
        | ProgramType::RawTracePoint
        | ProgramType::LwtSeg6local
        | ProgramType::RawTracePointWritable
        | ProgramType::StructOps
        | ProgramType::Extension
        | ProgramType::Syscall => None,
    };

    match program_type {
        ProgramType::KProbe => {
            if let Ok(current_version) = KernelVersion::current() {
                u.kern_version = current_version.code();
            }
        }
        // syscall required to be sleepable: https://elixir.bootlin.com/linux/v5.14/source/kernel/bpf/verifier.c#L13240
        ProgramType::Syscall => u.prog_flags = aya_obj::generated::BPF_F_SLEEPABLE,
        _ => {}
    }

    let program_type: bpf_prog_type = program_type.into();
    u.prog_type = program_type as u32;
    if let Some(expected_attach_type) = expected_attach_type {
        u.expected_attach_type = expected_attach_type as u32;
    }

    op(&mut attr)
}

pub(crate) fn is_probe_read_kernel_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let mov64_reg = (BPF_ALU64 | BPF_MOV | BPF_X) as u8;
    let add64_imm = (BPF_ALU64 | BPF_ADD | BPF_K) as u8;
    let mov64_imm = (BPF_ALU64 | BPF_MOV | BPF_K) as u8;
    let call = (BPF_JMP | BPF_CALL) as u8;
    let exit = (BPF_JMP | BPF_EXIT) as u8;
    let insns = [
        new_insn(mov64_reg, 1, 10, 0, 0),
        new_insn(add64_imm, 1, 0, 0, -8),
        new_insn(mov64_imm, 2, 0, 0, 8),
        new_insn(mov64_imm, 3, 0, 0, 0),
        new_insn(call, 0, 0, 0, BPF_FUNC_probe_read_kernel as i32),
        new_insn(exit, 0, 0, 0, 0),
    ];

    let gpl = c"GPL";
    u.license = gpl.as_ptr() as u64;

    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT as u32;

    bpf_prog_load(&mut attr).is_ok()
}

pub(crate) fn is_perf_link_supported() -> bool {
    with_trivial_prog(ProgramType::TracePoint, |attr| {
        if let Ok(fd) = bpf_prog_load(attr) {
            let fd = fd.as_fd();
            // Uses an invalid target FD so we get EBADF if supported.
            let link = bpf_link_create(
                fd,
                LinkTarget::IfIndex(u32::MAX),
                bpf_attach_type::BPF_PERF_EVENT,
                0,
                None,
            );
            // Returns EINVAL if unsupported. EBADF if supported.
            matches!(link, Err(err) if err.raw_os_error() == Some(EBADF))
        } else {
            false
        }
    })
}

pub(crate) fn is_bpf_global_data_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let map = MapData::create(
        aya_obj::Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                key_size: 4,
                value_size: 32,
                max_entries: 1,
                ..Default::default()
            },
            section_index: 0,
            section_kind: EbpfSectionKind::Maps,
            symbol_index: None,
            data: Vec::new(),
        }),
        "aya_global",
        None,
    );

    if let Ok(map) = map {
        let ld_map_value = (BPF_LD | BPF_DW | BPF_IMM) as u8;
        let pseudo_map_value = BPF_PSEUDO_MAP_VALUE as u8;
        let fd = map.fd().as_fd().as_raw_fd();
        let st_mem = (BPF_ST | BPF_DW | BPF_MEM) as u8;
        let mov64_imm = (BPF_ALU64 | BPF_MOV | BPF_K) as u8;
        let exit = (BPF_JMP | BPF_EXIT) as u8;
        let insns = [
            new_insn(ld_map_value, 1, pseudo_map_value, 0, fd),
            new_insn(0, 0, 0, 0, 0),
            new_insn(st_mem, 1, 0, 0, 42),
            new_insn(mov64_imm, 0, 0, 0, 0),
            new_insn(exit, 0, 0, 0, 0),
        ];

        let gpl = c"GPL";
        u.license = gpl.as_ptr() as u64;
        u.insn_cnt = insns.len() as u32;
        u.insns = insns.as_ptr() as u64;
        u.prog_type = bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32;

        bpf_prog_load(&mut attr).is_ok()
    } else {
        false
    }
}

pub(crate) fn is_bpf_cookie_supported() -> bool {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let call = (BPF_JMP | BPF_CALL) as u8;
    let exit = (BPF_JMP | BPF_EXIT) as u8;
    let insns = [
        new_insn(call, 0, 0, 0, BPF_FUNC_get_attach_cookie as i32),
        new_insn(exit, 0, 0, 0, 0),
    ];

    let gpl = c"GPL";
    u.license = gpl.as_ptr() as u64;

    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = bpf_prog_type::BPF_PROG_TYPE_KPROBE as u32;

    bpf_prog_load(&mut attr).is_ok()
}

/// Tests whether CpuMap, DevMap and DevMapHash support program ids
pub(crate) fn is_prog_id_supported(map_type: bpf_map_type) -> bool {
    assert_matches!(
        map_type,
        bpf_map_type::BPF_MAP_TYPE_CPUMAP
            | bpf_map_type::BPF_MAP_TYPE_DEVMAP
            | bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH
    );

    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_1 };

    u.map_type = map_type as u32;
    u.key_size = 4;
    u.value_size = 8; // 4 for CPU ID, 8 for CPU ID + prog ID
    u.max_entries = 1;
    u.map_flags = 0;

    bpf_map_create(&mut attr).is_ok()
}

pub(crate) fn is_btf_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("int");
    let int_type = BtfType::Int(Int::new(name_offset, 4, IntEncoding::Signed, 0));
    btf.add_type(int_type);
    let btf_bytes = btf.to_bytes();
    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
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

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
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

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
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

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_datasec_zero_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string(".empty");
    let datasec_type = BtfType::DataSec(DataSec::new(name_offset, Vec::new(), 0));
    btf.add_type(datasec_type);

    bpf_load_btf(btf.to_bytes().as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_enum64_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("enum64");

    let enum_64_type = BtfType::Enum64(Enum64::new(
        name_offset,
        true,
        vec![BtfEnum64::new(btf.add_string("a"), 1)],
    ));
    btf.add_type(enum_64_type);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(crate) fn is_btf_float_supported() -> bool {
    let mut btf = Btf::new();
    let name_offset = btf.add_string("float");
    let float_type = BtfType::Float(Float::new(name_offset, 16));
    btf.add_type(float_type);

    let btf_bytes = btf.to_bytes();

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
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

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
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

    bpf_load_btf(btf_bytes.as_slice(), &mut [], Default::default()).is_ok()
}

pub(super) fn bpf_prog_load(attr: &mut bpf_attr) -> io::Result<crate::MockableFd> {
    // SAFETY: BPF_PROG_LOAD returns a new file descriptor.
    with_raised_rlimit_retry(|| unsafe { fd_sys_bpf(bpf_cmd::BPF_PROG_LOAD, attr) })
}

fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    syscall(Syscall::Ebpf { cmd, attr }).map_err(|(code, io_error)| {
        assert_eq!(code, -1);
        io_error
    })
}

pub(super) fn unit_sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<()> {
    sys_bpf(cmd, attr).map(|code| assert_eq!(code, 0))
}

fn bpf_obj_get_next_id(
    id: u32,
    cmd: bpf_cmd,
    name: &'static str,
) -> Result<Option<u32>, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_6 };
    u.__bindgen_anon_1.start_id = id;
    match unit_sys_bpf(cmd, &mut attr) {
        Ok(()) => Ok(Some(unsafe { attr.__bindgen_anon_6.next_id })),
        Err(io_error) => {
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

fn iter_obj_ids(
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

/// Introduced in kernel v4.13.
pub(crate) fn iter_prog_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_PROG_GET_NEXT_ID, "bpf_prog_get_next_id")
}

pub(crate) fn iter_link_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_LINK_GET_NEXT_ID, "bpf_link_get_next_id")
}

/// Introduced in kernel v4.13.
pub(crate) fn iter_map_ids() -> impl Iterator<Item = Result<u32, SyscallError>> {
    iter_obj_ids(bpf_cmd::BPF_MAP_GET_NEXT_ID, "bpf_map_get_next_id")
}

/// Introduced in kernel v5.8.
pub(crate) fn bpf_enable_stats(
    stats_type: bpf_stats_type,
) -> Result<crate::MockableFd, SyscallError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.enable_stats.type_ = stats_type as u32;

    // SAFETY: BPF_ENABLE_STATS returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_ENABLE_STATS, &mut attr) }.map_err(|io_error| SyscallError {
        call: "bpf_enable_stats",
        io_error,
    })
}

pub(crate) fn retry_with_verifier_logs<T>(
    max_retries: usize,
    f: impl Fn(&mut [u8]) -> io::Result<T>,
) -> (io::Result<T>, VerifierLog) {
    const MIN_LOG_BUF_SIZE: usize = 1024 * 10;
    const MAX_LOG_BUF_SIZE: usize = (u32::MAX >> 8) as usize;

    let mut log_buf = Vec::new();
    let mut retries = 0;
    loop {
        let ret = f(log_buf.as_mut_slice());
        if retries != max_retries {
            if let Err(io_error) = &ret {
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

        break (ret, VerifierLog::new(log_buf));
    }
}

#[cfg(test)]
mod tests {
    use libc::EINVAL;

    use super::*;
    use crate::sys::override_syscall;

    #[test]
    fn test_attach_with_attributes() {
        const FAKE_FLAGS: u32 = 1234;
        const FAKE_FD: i32 = 4321;

        // Test attach flags propagated to system call.
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_PROG_ATTACH,
                attr,
            } => {
                assert_eq!(unsafe { attr.__bindgen_anon_5.attach_flags }, FAKE_FLAGS);
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EINVAL))),
        });

        let prog_fd = unsafe { BorrowedFd::borrow_raw(FAKE_FD) };
        let tgt_fd = unsafe { BorrowedFd::borrow_raw(FAKE_FD) };
        let mut result = bpf_prog_attach(
            prog_fd,
            tgt_fd,
            bpf_attach_type::BPF_CGROUP_SOCK_OPS,
            FAKE_FLAGS,
        );
        result.unwrap();

        // Test with no flags.
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_PROG_ATTACH,
                attr,
            } => {
                assert_eq!(unsafe { attr.__bindgen_anon_5.attach_flags }, 0);
                Ok(0)
            }
            _ => Err((-1, io::Error::from_raw_os_error(EINVAL))),
        });

        result = bpf_prog_attach(prog_fd, tgt_fd, bpf_attach_type::BPF_CGROUP_SOCK_OPS, 0);
        result.unwrap();
    }

    #[test]
    fn test_perf_link_supported() {
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Err((-1, io::Error::from_raw_os_error(EBADF))),
            _ => Ok(crate::MockableFd::mock_signed_fd().into()),
        });
        let supported = is_perf_link_supported();
        assert!(supported);

        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_LINK_CREATE,
                ..
            } => Err((-1, io::Error::from_raw_os_error(EINVAL))),
            _ => Ok(crate::MockableFd::mock_signed_fd().into()),
        });
        let supported = is_perf_link_supported();
        assert!(!supported);
    }

    #[test]
    fn test_prog_id_supported() {
        override_syscall(|_call| Ok(crate::MockableFd::mock_signed_fd().into()));

        // Ensure that the three map types we can check are accepted
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_CPUMAP);
        assert!(supported);
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_DEVMAP);
        assert!(supported);
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH);
        assert!(supported);

        override_syscall(|_call| Err((-1, io::Error::from_raw_os_error(EINVAL))));
        let supported = is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_CPUMAP);
        assert!(!supported);
    }

    #[test]
    #[should_panic = "assertion failed: `BPF_MAP_TYPE_HASH` does not match `bpf_map_type::BPF_MAP_TYPE_CPUMAP | bpf_map_type::BPF_MAP_TYPE_DEVMAP |
bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH`"]
    fn test_prog_id_supported_reject_types() {
        is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_HASH);
    }
}
