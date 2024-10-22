//! Probes and identifies available eBPF features supported by the host kernel.

use std::{mem, os::fd::AsRawFd};

use aya_obj::generated::{
    bpf_attach_type, bpf_attr, bpf_cmd, bpf_insn, bpf_prog_info, BPF_F_MMAPABLE, BPF_F_NO_PREALLOC,
    BPF_F_SLEEPABLE,
};
use libc::{E2BIG, EINVAL};

use super::{bpf_prog_load, fd_sys_bpf, sys_bpf, SyscallError};
use crate::{
    maps::MapType,
    programs::ProgramType,
    util::{page_size, KernelVersion},
    MockableFd,
};

const RETURN_ZERO_INSNS: &[bpf_insn] = &[
    bpf_insn::new(0xb7, 0, 0, 0, 0), // mov64 r0 = 0
    bpf_insn::new(0x95, 0, 0, 0, 0), // exit
];
const GPL_COMPATIBLE: &[u8; 4] = b"GPL\0";

/// Whether the host kernel supports the [`ProgramType`].
///
/// # Examples
///
/// ```no_run
/// # use aya::{
/// #     programs::ProgramType,
/// #     sys::feature_probe::is_program_supported,
/// # };
/// #
/// match is_program_supported(ProgramType::Xdp) {
///     Ok(true) => println!("XDP supported :)"),
///     Ok(false) => println!("XDP not supported :("),
///     Err(err) => println!("Uh oh! Unexpected error: {:?}", err),
/// }
/// ```
///
/// # Errors
///
/// Returns [`SyscallError`] if kernel probing fails with an unexpected error.
///
/// Note that certain errors are expected and handled internally; only
/// unanticipated failures during probing will result in this error.
pub fn is_program_supported(program_type: ProgramType) -> Result<bool, SyscallError> {
    if program_type == ProgramType::Unspecified {
        return Ok(false);
    }

    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: union access
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    // `bpf_prog_load_fixup_attach_type()` sets this for us for cgroup_sock and
    // and sk_reuseport.
    let expected_attach_type = match program_type {
        ProgramType::CgroupSkb => Some(bpf_attach_type::BPF_CGROUP_INET_INGRESS),
        ProgramType::CgroupSockAddr => Some(bpf_attach_type::BPF_CGROUP_INET4_BIND),
        ProgramType::CgroupSockopt => Some(bpf_attach_type::BPF_CGROUP_GETSOCKOPT),
        ProgramType::SkLookup => Some(bpf_attach_type::BPF_SK_LOOKUP),
        ProgramType::Netfilter => Some(bpf_attach_type::BPF_NETFILTER),
        _ => None,
    };

    // Intentionally trigger `EINVAL` for some prog types, and use verifier
    // logs to help confirm whether the variant actually exists.
    let mut verifier_log = [0_u8; libc::PATH_MAX as usize];

    match program_type {
        ProgramType::KProbe => u.kern_version = KernelVersion::current().unwrap().code(),
        ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm => {
            u.log_buf = verifier_log.as_mut_ptr() as _;
            u.log_size = libc::PATH_MAX as _;
            u.log_level = 1;
        }
        ProgramType::Syscall => u.prog_flags = BPF_F_SLEEPABLE,
        _ => {}
    }

    u.prog_type = program_type as u32;
    u.insn_cnt = 2;
    u.insns = RETURN_ZERO_INSNS.as_ptr() as u64;
    u.license = GPL_COMPATIBLE.as_ptr() as u64;
    if let Some(expected_attach_type) = expected_attach_type {
        u.expected_attach_type = expected_attach_type as u32;
    }

    let io_error = match bpf_prog_load(&mut attr) {
        Ok(_) => return Ok(true),
        Err((_, io_error)) => io_error,
    };
    match io_error.raw_os_error() {
        Some(EINVAL) => {
            // verifier/`bpf_check_attach_target()` produces same log message
            // for these types (due to `attach_btf_id` unset)
            let supported = matches!(
                program_type, ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm
                if verifier_log.starts_with(b"Tracing programs must provide btf_id")
            );

            Ok(supported)
        }
        // `E2BIG` when accessing/using fields that are not available
        // e.g. `expected_attach_type`
        Some(E2BIG) => Ok(false),
        // `ENOTSUPP` from verifier/`check_struct_ops_btf_id()` for struct_ops
        Some(524) if program_type == ProgramType::StructOps => Ok(true),
        _ => Err(SyscallError {
            call: "bpf_prog_load",
            io_error,
        }),
    }
}

/// Whether the host kernel supports the [`MapType`].
///
/// # Examples
///
/// ```no_run
/// # use aya::{
/// #     maps::MapType,
/// #     sys::feature_probe::is_map_supported,
/// # };
/// #
/// match is_map_supported(MapType::HashOfMaps) {
///     Ok(true) => println!("hash_of_maps supported :)"),
///     Ok(false) => println!("hash_of_maps not supported :("),
///     Err(err) => println!("Uh oh! Unexpected error: {:?}", err),
/// }
/// ```
///
/// # Errors
///
/// Returns [`SyscallError`] if kernel probing fails with an unexpected error.
///
/// Note that certain errors are expected and handled internally; only
/// unanticipated failures during probing will result in this error.
pub fn is_map_supported(map_type: MapType) -> Result<bool, SyscallError> {
    if map_type == MapType::Unspecified {
        return Ok(false);
    }

    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: union access
    let u = unsafe { &mut attr.__bindgen_anon_1 };

    // To pass `map_alloc_check`/`map_alloc`
    let key_size = match map_type {
        MapType::LpmTrie | MapType::CgroupStorage | MapType::PerCpuCgroupStorage => 16,
        MapType::Queue
        | MapType::Stack
        | MapType::RingBuf
        | MapType::BloomFilter
        | MapType::UserRingBuf
        | MapType::Arena => 0,
        _ => 4,
    };
    let value_size = match map_type {
        MapType::StackTrace | MapType::LpmTrie => 8,
        MapType::SkStorage
        | MapType::InodeStorage
        | MapType::TaskStorage
        | MapType::CgrpStorage => {
            // Intentionally trigger `E2BIG` from
            // `bpf_local_storage_map_alloc_check()`.
            u32::MAX
        }
        MapType::RingBuf | MapType::UserRingBuf | MapType::Arena => 0,
        _ => 4,
    };
    let max_entries = match map_type {
        MapType::CgroupStorage
        | MapType::PerCpuCgroupStorage
        | MapType::SkStorage
        | MapType::InodeStorage
        | MapType::TaskStorage
        | MapType::CgrpStorage => 0,
        MapType::RingBuf | MapType::UserRingBuf => page_size() as u32,
        _ => 1,
    };

    let inner_map_fd;
    match map_type {
        MapType::LpmTrie => u.map_flags = BPF_F_NO_PREALLOC,
        MapType::SkStorage
        | MapType::InodeStorage
        | MapType::TaskStorage
        | MapType::CgrpStorage => {
            u.map_flags = BPF_F_NO_PREALLOC;
            u.btf_key_type_id = 1;
            u.btf_value_type_id = 1;
        }
        MapType::ArrayOfMaps | MapType::HashOfMaps => {
            inner_map_fd = dummy_map()?;
            u.inner_map_fd = inner_map_fd.as_raw_fd() as u32;
        }
        MapType::StructOps => u.btf_vmlinux_value_type_id = 1,
        MapType::Arena => u.map_flags = BPF_F_MMAPABLE,
        _ => {}
    }

    u.map_type = map_type as u32;
    u.key_size = key_size;
    u.value_size = value_size;
    u.max_entries = max_entries;

    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    let io_error = match unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr) } {
        Ok(_) => return Ok(true),
        Err((_, io_error)) => io_error,
    };
    match io_error.raw_os_error() {
        Some(EINVAL) => Ok(false),
        Some(E2BIG)
            if matches!(
                map_type,
                MapType::SkStorage
                    | MapType::InodeStorage
                    | MapType::TaskStorage
                    | MapType::CgrpStorage
            ) =>
        {
            Ok(true)
        }
        // `ENOTSUPP` from `bpf_struct_ops_map_alloc()` for struct_ops
        Some(524) if map_type == MapType::StructOps => Ok(true),
        _ => Err(SyscallError {
            call: "bpf_map_create",
            io_error,
        }),
    }
}

/// Create a map and return its fd.
fn dummy_map() -> Result<crate::MockableFd, SyscallError> {
    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: union access
    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = 1;
    u.key_size = 1;
    u.value_size = 1;
    u.max_entries = 1;

    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr) }.map_err(|(_, io_error)| {
        SyscallError {
            call: "bpf_map_create",
            io_error,
        }
    })
}

/// Whether `nr_map_ids` & `map_ids` fields in `bpf_prog_info` are supported.
pub(crate) fn is_prog_info_map_ids_supported() -> Result<bool, SyscallError> {
    let fd = dummy_prog()?;

    // SAFETY: all-zero byte-pattern valid for `bpf_prog_info`
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    info.nr_map_ids = 1;

    probe_bpf_info(fd, info)
}

/// Tests whether `bpf_prog_info.gpl_compatible` field is supported.
pub(crate) fn is_prog_info_license_supported() -> Result<bool, SyscallError> {
    let fd = dummy_prog()?;

    // SAFETY: all-zero byte-pattern valid for `bpf_prog_info`
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    info.set_gpl_compatible(1);

    probe_bpf_info(fd, info)
}

/// Probes program and map info.
fn probe_bpf_info<T>(fd: MockableFd, info: T) -> Result<bool, SyscallError> {
    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info_len = mem::size_of_val(&info) as u32;
    attr.info.info = &info as *const _ as u64;

    let io_error = match sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
        Ok(_) => return Ok(true),
        Err((_, io_error)) => io_error,
    };
    match io_error.raw_os_error() {
        // `E2BIG` from `bpf_check_uarg_tail_zero()`
        Some(E2BIG) => Ok(false),
        _ => Err(SyscallError {
            call: "bpf_obj_get_info_by_fd",
            io_error,
        }),
    }
}

/// Create a program and returns its fd.
fn dummy_prog() -> Result<crate::MockableFd, SyscallError> {
    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: union access
    let u = unsafe { &mut attr.__bindgen_anon_3 };
    u.prog_type = 1;
    u.insn_cnt = 2;
    u.insns = RETURN_ZERO_INSNS.as_ptr() as u64;
    u.license = GPL_COMPATIBLE.as_ptr() as u64;

    bpf_prog_load(&mut attr).map_err(|(_, io_error)| SyscallError {
        call: "bpf_prog_load",
        io_error,
    })
}
