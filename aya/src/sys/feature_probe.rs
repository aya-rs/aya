//! Probes and identifies available eBPF features supported by the host kernel.

use std::{mem, os::fd::AsRawFd as _};

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{BPF_F_MMAPABLE, BPF_F_NO_PREALLOC, bpf_attr, bpf_cmd, bpf_map_type},
};
use libc::{E2BIG, EBADF, EINVAL};

use super::{SyscallError, bpf_prog_load, fd_sys_bpf, with_trivial_prog};
use crate::{
    maps::MapType,
    programs::{ProgramError, ProgramType},
    util::page_size,
};

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
/// Returns [`ProgramError::SyscallError`] if a syscall fails with an unexpected
/// error, or [`ProgramError::Btf`] for BTF related errors.
///
/// Certain errors are expected and handled internally; only unanticipated
/// failures during probing will result in these errors.
pub fn is_program_supported(program_type: ProgramType) -> Result<bool, ProgramError> {
    if program_type == ProgramType::Unspecified {
        return Ok(false);
    }

    let mut verifier_log = [0_u8; libc::PATH_MAX as usize];
    let attach_btf_id = if matches!(program_type, ProgramType::Tracing | ProgramType::Lsm) {
        let func_name = if program_type == ProgramType::Tracing {
            "bpf_fentry_test1"
        } else {
            "bpf_lsm_bpf"
        };
        Btf::from_sys_fs()
            .and_then(|btf| btf.id_by_type_name_kind(func_name, BtfKind::Func))
            .unwrap_or(0)
    } else {
        0
    };

    let error = match with_trivial_prog(program_type, |attr| {
        // SAFETY: union access
        let u = unsafe { &mut attr.__bindgen_anon_3 };

        u.attach_btf_id = attach_btf_id;
        match program_type {
            ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm => {
                u.log_buf = verifier_log.as_mut_ptr() as u64;
                u.log_level = 1;
                u.log_size = verifier_log.len() as u32;
            }
            _ => {}
        }

        bpf_prog_load(attr).err().map(|io_error| {
            ProgramError::SyscallError(SyscallError {
                call: "bpf_prog_load",
                io_error,
            })
        })
    }) {
        Some(err) => err,
        None => return Ok(true),
    };

    match &error {
        ProgramError::SyscallError(err) => {
            match err.io_error.raw_os_error() {
                Some(EINVAL) => {
                    // verifier/`bpf_check_attach_target()` (or `check_attach_btf_id()` on older
                    // kernels) produces this log message for these prog types if `attach_btf_id`
                    // is unset
                    let supported = matches!(
                        program_type,
                        ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm
                            if verifier_log.starts_with(b"Tracing programs must provide btf_id"));
                    Ok(supported)
                }
                Some(E2BIG) => Ok(false),
                // `ENOTSUPP` from verifier/`check_struct_ops_btf_id()` for struct_ops
                Some(524) if program_type == ProgramType::StructOps => Ok(true),
                _ => Err(error),
            }
        }
        _ => Err(error),
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

    // Ensure that fd doesn't get dropped due to scoping.
    let inner_map_fd;
    match map_type {
        MapType::LpmTrie => u.map_flags = BPF_F_NO_PREALLOC,
        MapType::SkStorage
        | MapType::InodeStorage
        | MapType::TaskStorage
        | MapType::CgrpStorage => {
            u.map_flags = BPF_F_NO_PREALLOC;
            // Intentionally trigger `EBADF` from `btf_get_by_fd()`.
            u.btf_fd = u32::MAX;
            u.btf_key_type_id = 1;
            u.btf_value_type_id = 1;
        }
        MapType::ArrayOfMaps | MapType::HashOfMaps => {
            // SAFETY: all-zero byte-pattern valid for `bpf_attr`
            let mut attr_map = unsafe { mem::zeroed::<bpf_attr>() };
            // SAFETY: union access
            let u_map = unsafe { &mut attr_map.__bindgen_anon_1 };
            u_map.map_type = bpf_map_type::BPF_MAP_TYPE_HASH as u32;
            u_map.key_size = 1;
            u_map.value_size = 1;
            u_map.max_entries = 1;
            // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
            inner_map_fd = unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr_map) }.map_err(
                |io_error| SyscallError {
                    call: "bpf_map_create",
                    io_error,
                },
            )?;

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
        Err(io_error) => io_error,
    };
    match io_error.raw_os_error() {
        Some(EINVAL) => Ok(false),
        Some(E2BIG)
            if matches!(
                map_type,
                MapType::SkStorage
                    | MapType::StructOps
                    | MapType::InodeStorage
                    | MapType::TaskStorage
                    | MapType::CgrpStorage
            ) =>
        {
            Ok(false)
        }
        Some(EBADF)
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
        // `ENOTSUPP` from `bpf_struct_ops_map_alloc()` for struct_ops.
        Some(524) if map_type == MapType::StructOps => Ok(true),
        _ => Err(SyscallError {
            call: "bpf_map_create",
            io_error,
        }),
    }
}
