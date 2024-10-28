//! Probes and identifies available eBPF features supported by the host kernel.

use std::{io::ErrorKind, mem, os::fd::AsRawFd as _};

use aya_obj::{
    btf::{Btf, BtfError, BtfKind},
    generated::{
        BPF_F_MMAPABLE, BPF_F_NO_PREALLOC, BPF_F_SLEEPABLE, bpf_attach_type, bpf_attr, bpf_cmd,
        bpf_map_type, bpf_prog_info,
    },
};
use libc::{E2BIG, EBADF, EINVAL};

use super::{SyscallError, bpf_prog_load, fd_sys_bpf, unit_sys_bpf, with_trivial_prog};
use crate::{
    MockableFd,
    maps::MapType,
    programs::{ProgramError, ProgramType},
    util::{KernelVersion, page_size},
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

    let mut verifier_log = match program_type {
        ProgramType::Extension => vec![0_u8; libc::PATH_MAX as usize],
        _ => vec![],
    };
    let error = match create_minimal_program(program_type, &mut verifier_log) {
        Ok(_) => return Ok(true),
        Err(err) => err,
    };
    match error {
        ProgramError::SyscallError(err) if matches!(err.io_error.raw_os_error(), Some(EINVAL)) => {
            // verifier/`bpf_check_attach_target()` produces same log message
            // for these types due to unset `attach_btf_id`
            let supported = program_type == ProgramType::Extension
                && verifier_log.starts_with(b"Tracing programs must provide btf_id");
            Ok(supported)
        }
        ProgramError::SyscallError(err) if matches!(err.io_error.raw_os_error(), Some(E2BIG)) => {
            Ok(false)
        }
        ProgramError::SyscallError(err)
            // `ENOTSUPP` from verifier/`check_struct_ops_btf_id()` for struct_ops
            if matches!(err.io_error.raw_os_error(), Some(524))
                && program_type == ProgramType::StructOps =>
        {
            Ok(true)
        }
        ProgramError::Btf(BtfError::FileError { error, .. })
            if error.kind() == ErrorKind::NotFound =>
        {
            Ok(false)
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
        MapType::InodeStorage => {
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
        Some(E2BIG) if map_type == MapType::InodeStorage => Ok(true),
        Some(E2BIG)
            if matches!(
                map_type,
                MapType::SkStorage
                    | MapType::StructOps
                    | MapType::TaskStorage
                    | MapType::CgrpStorage
            ) =>
        {
            Ok(false)
        }
        Some(EBADF)
            if matches!(
                map_type,
                MapType::SkStorage | MapType::TaskStorage | MapType::CgrpStorage
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

/// Whether `nr_map_ids` & `map_ids` fields in `bpf_prog_info` are supported.
pub(crate) fn is_prog_info_map_ids_supported() -> Result<bool, ProgramError> {
    let fd = create_minimal_program(ProgramType::SocketFilter, &mut [])?;
    // SAFETY: all-zero byte-pattern valid for `bpf_prog_info`
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    info.nr_map_ids = 1;

    probe_bpf_info(fd, info).map_err(ProgramError::from)
}

/// Tests whether `bpf_prog_info.gpl_compatible` field is supported.
pub(crate) fn is_prog_info_license_supported() -> Result<bool, ProgramError> {
    let fd = create_minimal_program(ProgramType::SocketFilter, &mut [])?;
    // SAFETY: all-zero byte-pattern valid for `bpf_prog_info`
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    info.set_gpl_compatible(1);

    probe_bpf_info(fd, info).map_err(ProgramError::from)
}

/// Create a minimal program with the specified type.
/// Types not created for `Extension` and `StructOps`.
fn create_minimal_program(
    program_type: ProgramType,
    verifier_log: &mut [u8],
) -> Result<crate::MockableFd, ProgramError> {
    with_trivial_prog(|attr| {
        // SAFETY: union access
        let u = unsafe { &mut attr.__bindgen_anon_3 };

        // `bpf_prog_load_fixup_attach_type()` sets this for us for cgroup_sock and
        // and sk_reuseport.
        let expected_attach_type = match program_type {
            ProgramType::CgroupSkb => Some(bpf_attach_type::BPF_CGROUP_INET_INGRESS),
            ProgramType::CgroupSockAddr => Some(bpf_attach_type::BPF_CGROUP_INET4_BIND),
            ProgramType::CgroupSockopt => Some(bpf_attach_type::BPF_CGROUP_GETSOCKOPT),
            ProgramType::Tracing => Some(bpf_attach_type::BPF_TRACE_FENTRY),
            ProgramType::Lsm => Some(bpf_attach_type::BPF_LSM_MAC),
            ProgramType::SkLookup => Some(bpf_attach_type::BPF_SK_LOOKUP),
            ProgramType::Netfilter => Some(bpf_attach_type::BPF_NETFILTER),
            _ => None,
        };

        match program_type {
            ProgramType::KProbe => u.kern_version = KernelVersion::current().unwrap().code(),
            ProgramType::Tracing | ProgramType::Lsm => {
                let btf = Btf::from_sys_fs()?;
                let func_name = match program_type {
                    ProgramType::Tracing => "bpf_fentry_test1",
                    _ => "bpf_lsm_bpf",
                };
                u.attach_btf_id = btf.id_by_type_name_kind(func_name, BtfKind::Func)?;
            }
            ProgramType::Extension => {
                u.log_buf = verifier_log.as_mut_ptr() as u64;
                u.log_level = 1;
                u.log_size = verifier_log.len() as u32;
            }
            ProgramType::Syscall => u.prog_flags = BPF_F_SLEEPABLE,
            _ => {}
        }

        u.prog_type = program_type as u32;
        if let Some(expected_attach_type) = expected_attach_type {
            u.expected_attach_type = expected_attach_type as u32;
        }

        bpf_prog_load(attr).map_err(|io_error| {
            ProgramError::SyscallError(SyscallError {
                call: "bpf_prog_load",
                io_error,
            })
        })
    })
}

/// Probes program and map info.
fn probe_bpf_info<T>(fd: MockableFd, info: T) -> Result<bool, SyscallError> {
    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info_len = mem::size_of_val(&info) as u32;
    attr.info.info = &info as *const _ as u64;

    let io_error = match unit_sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr) {
        Ok(()) => return Ok(true),
        Err(io_error) => io_error,
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
