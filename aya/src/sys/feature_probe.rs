//! Probes and identifies available eBPF features supported by the host kernel.

use std::{mem, os::fd::AsRawFd as _};

use aya_obj::{
    btf::{Btf, BtfKind},
    generated::{
        BPF_F_MMAPABLE, BPF_F_NO_PREALLOC, bpf_attr, bpf_cmd, bpf_map_type, bpf_prog_info,
    },
};
use libc::{E2BIG, EBADF, EINVAL};

use super::{SyscallError, bpf_prog_load, fd_sys_bpf, unit_sys_bpf, with_trivial_prog};
use crate::{
    MockableFd,
    maps::MapType,
    programs::{ProgramError, ProgramType},
    util::page_size,
};

/// Whether the host kernel supports the [`ProgramType`].
///
/// # Examples
///
/// ```no_run
/// # use aya::{programs::ProgramType, sys::is_program_supported};
/// #
/// match is_program_supported(ProgramType::Xdp) {
///     Ok(true) => println!("XDP supported :)"),
///     Ok(false) => println!("XDP not supported :("),
///     Err(err) => println!("Uh oh! Unexpected error while probing: {:?}", err),
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

    // Verifier log is used in tracing, extension, and lsm to help detect support if loading fails.
    // The expected target message for these types is:
    // `Tracing programs must provide btf_id\nprocessed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n\0`
    // https://elixir.bootlin.com/linux/v5.5/source/kernel/bpf/verifier.c#L9535
    let mut verifier_log = [0_u8; 136];

    // The tracing and lsm types require a valid `attach_btf_id` for a successful load. However,
    // if the symbols cannot be found in the BTF, then leave the field unset/0.
    // Although extension also requires `attach_btf_id`, we intentionally leave it unset since a
    // successful load requires additional setup with another prog loaded with BTF.
    //
    // When `attach_btf_id` is unset, then loading will fail, and so we examine verifier log
    // for the expected message.
    let attach_btf_id = match program_type {
        // `bpf_fentry_test1` symbol from https://elixir.bootlin.com/linux/v5.5/source/net/bpf/test_run.c#L112
        ProgramType::Tracing => Some("bpf_fentry_test1"),
        // `bpf_lsm_bpf` symbol from https://elixir.bootlin.com/linux/v5.7/source/include/linux/lsm_hook_defs.h#L364
        // or https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/bpf_lsm.c#L135 on later versions
        ProgramType::Lsm => Some("bpf_lsm_bpf"),
        _ => None,
    }
    .map(|func_name| {
        Btf::from_sys_fs()
            .and_then(|btf| btf.id_by_type_name_kind(func_name, BtfKind::Func))
            .unwrap_or(0)
    });

    let error = match with_trivial_prog(program_type, |attr| {
        // SAFETY: union access
        let u = unsafe { &mut attr.__bindgen_anon_3 };

        if let Some(attach_btf_id) = attach_btf_id {
            u.attach_btf_id = attach_btf_id;
        }
        match program_type {
            // If loading fails for these types due to unset `attach_btf_id`, then we defer to
            // verifier log to verify whether type is supported.
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

    // Loading may fail for some types (namely tracing, extension, lsm, & struct_ops), so we
    // perform additional examination on the OS error and/or verifier logs.
    match &error {
        ProgramError::SyscallError(err) => {
            match err.io_error.raw_os_error() {
                // For most types, `EINVAL` typically indicates it is not supported.
                // However, further examination is required for tracing, extension, and lsm.
                Some(EINVAL) => {
                    // At this point for tracing, extension, and lsm, loading failed due to unset
                    // `attach_btf_id`, so we examine verifier log for the target message.
                    // Message originates in `check_attach_btf_id()` in v5.5 to v5.9 https://elixir.bootlin.com/linux/v5.5/source/kernel/bpf/verifier.c#L9535,
                    // then moved to `bpf_check_attach_target()` in 5.10 and onward https://elixir.bootlin.com/linux/v5.9/source/kernel/bpf/verifier.c#L10849.
                    //
                    // If target message is present in the logs, then loading process has reached
                    // up to the verifier section, which indicates that the kernel is at least
                    // aware of the program type variants.
                    // If logs is empty, then it was immediately rejected by the kernel, meaning
                    // the types are not supported.
                    let supported = matches!(
                        program_type,
                        ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm
                    ) && verifier_log
                        .starts_with(b"Tracing programs must provide btf_id");
                    Ok(supported)
                }
                // `E2BIG` from `bpf_check_uarg_tail_zero()` https://elixir.bootlin.com/linux/v4.18/source/kernel/bpf/syscall.c#L71
                // indicates that the kernel detected non-zero fields in `bpf_attr` that does not
                // exist at its current version.
                Some(E2BIG) => Ok(false),
                // `ENOTSUPP` from `check_struct_ops_btf_id()` https://elixir.bootlin.com/linux/v5.6/source/kernel/bpf/verifier.c#L9740
                // indicates that it reached the verifier section, meaning the kernel is at least
                // aware of the type's existence.  Otherwise, it will produce `EINVAL`, meaning the
                // type is immediately rejected and does not exist.
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
/// # use aya::{maps::MapType, sys::is_map_supported};
/// #
/// match is_map_supported(MapType::HashOfMaps) {
///     Ok(true) => println!("hash_of_maps supported :)"),
///     Ok(false) => println!("hash_of_maps not supported :("),
///     Err(err) => println!("Uh oh! Unexpected error while probing: {:?}", err),
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
    // Each `bpf_map_ops` struct contains their own `.map_alloc()` & `.map_alloc_check()` that does
    // field validation on map_create.
    let (key_size, value_size, max_entries) = match map_type {
        MapType::Unspecified => return Ok(false),
        MapType::Hash // https://elixir.bootlin.com/linux/v3.19/source/kernel/bpf/hashtab.c#L349
        | MapType::PerCpuHash  // https://elixir.bootlin.com/linux/v4.6/source/kernel/bpf/hashtab.c#L726
        | MapType::LruHash // https://elixir.bootlin.com/linux/v4.10/source/kernel/bpf/hashtab.c#L1032
        | MapType::LruPerCpuHash // https://elixir.bootlin.com/linux/v4.10/source/kernel/bpf/hashtab.c#L1133
            => (1, 1, 1),
        MapType::Array // https://elixir.bootlin.com/linux/v3.19/source/kernel/bpf/arraymap.c#L138
        | MapType::PerCpuArray // https://elixir.bootlin.com/linux/v4.6/source/kernel/bpf/arraymap.c#L283
            => (4, 1, 1),
        MapType::ProgramArray // https://elixir.bootlin.com/linux/v4.2/source/kernel/bpf/arraymap.c#L239
        | MapType::PerfEventArray // https://elixir.bootlin.com/linux/v4.3/source/kernel/bpf/arraymap.c#L312
        | MapType::CgroupArray // https://elixir.bootlin.com/linux/v4.8/source/kernel/bpf/arraymap.c#L562
        | MapType::ArrayOfMaps // https://elixir.bootlin.com/linux/v4.12/source/kernel/bpf/arraymap.c#L595
        | MapType::DevMap // https://elixir.bootlin.com/linux/v4.14/source/kernel/bpf/devmap.c#L360
        | MapType::SockMap // https://elixir.bootlin.com/linux/v4.14/source/kernel/bpf/sockmap.c#L874
        | MapType::CpuMap // https://elixir.bootlin.com/linux/v4.15/source/kernel/bpf/cpumap.c#L589
        | MapType::XskMap // https://elixir.bootlin.com/linux/v4.18/source/kernel/bpf/xskmap.c#L224
        | MapType::ReuseportSockArray // https://elixir.bootlin.com/linux/v4.20/source/kernel/bpf/reuseport_array.c#L357
        | MapType::DevMapHash // https://elixir.bootlin.com/linux/v5.4/source/kernel/bpf/devmap.c#L713
            => (4, 4, 1),
        MapType::StackTrace // https://elixir.bootlin.com/linux/v4.6/source/kernel/bpf/stackmap.c#L272
            => (4, 8, 1),
        MapType::LpmTrie // https://elixir.bootlin.com/linux/v4.11/source/kernel/bpf/lpm_trie.c#L509
            => (8, 1, 1),
        MapType::HashOfMaps // https://elixir.bootlin.com/linux/v4.12/source/kernel/bpf/hashtab.c#L1301
        | MapType::SockHash // https://elixir.bootlin.com/linux/v4.18/source/kernel/bpf/sockmap.c#L2507
            => (1, 4, 1),
        MapType::CgroupStorage // https://elixir.bootlin.com/linux/v4.19/source/kernel/bpf/local_storage.c#L246
        | MapType::PerCpuCgroupStorage // https://elixir.bootlin.com/linux/v4.20/source/kernel/bpf/local_storage.c#L313
            => (16, 1, 0),
        MapType::Queue // https://elixir.bootlin.com/linux/v4.20/source/kernel/bpf/queue_stack_maps.c#L267
        | MapType::Stack // https://elixir.bootlin.com/linux/v4.20/source/kernel/bpf/queue_stack_maps.c#L280
        | MapType::BloomFilter // https://elixir.bootlin.com/linux/v5.16/source/kernel/bpf/bloom_filter.c#L193
            => (0, 1, 1),
        MapType::SkStorage // https://elixir.bootlin.com/linux/v5.2/source/net/core/bpf_sk_storage.c#L779
        | MapType::InodeStorage // https://elixir.bootlin.com/linux/v5.10/source/kernel/bpf/bpf_inode_storage.c#L239
        | MapType::TaskStorage // https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/bpf_task_storage.c#L285
        | MapType::CgrpStorage // https://elixir.bootlin.com/linux/v6.2/source/kernel/bpf/bpf_cgrp_storage.c#L216
            => (4, 1, 0),
        MapType::StructOps // https://elixir.bootlin.com/linux/v5.6/source/kernel/bpf/bpf_struct_ops.c#L607
            => (4, 0, 1),
        MapType::RingBuf // https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/ringbuf.c#L296
        | MapType::UserRingBuf // https://elixir.bootlin.com/linux/v6.1/source/kernel/bpf/ringbuf.c#L356
        // `max_entries` required to be multiple of kernel page size & power of 2: https://elixir.bootlin.com/linux/v5.8/source/kernel/bpf/ringbuf.c#L160
            => (0, 0, page_size() as u32),
        MapType::Arena // https://elixir.bootlin.com/linux/v6.9/source/kernel/bpf/arena.c#L380
            => (0, 0, 1),
    };

    // SAFETY: all-zero byte-pattern valid for `bpf_attr`
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: union access
    let u = unsafe { &mut attr.__bindgen_anon_1 };
    u.map_type = map_type as u32;
    u.key_size = key_size;
    u.value_size = value_size;
    u.max_entries = max_entries;

    // Ensure that fd doesn't get dropped due to scoping for for *_of_maps type.
    let inner_map_fd: MockableFd;
    match map_type {
        // lpm_trie required to not be pre-alloced: https://elixir.bootlin.com/linux/v4.11/source/kernel/bpf/lpm_trie.c#L419
        MapType::LpmTrie => u.map_flags = BPF_F_NO_PREALLOC,
        // For these types, we aim to intentionally trigger `EBADF` by supplying invalid btf attach
        // data to verify the map type's existance. Otherwise, negative support will produce
        // `EINVAL` instead.
        MapType::SkStorage
        | MapType::InodeStorage
        | MapType::TaskStorage
        | MapType::CgrpStorage => {
            // These types required to not be pre-alloced:
            // - sk_storage: https://elixir.bootlin.com/linux/v5.2/source/net/core/bpf_sk_storage.c#L604
            // - inode_storage: https://elixir.bootlin.com/linux/v5.10/source/kernel/bpf/bpf_local_storage.c#L525
            // - task_storage: https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/bpf_local_storage.c#L527
            // - cgrp_storage: https://elixir.bootlin.com/linux/v6.2/source/kernel/bpf/bpf_local_storage.c#L539
            u.map_flags = BPF_F_NO_PREALLOC;
            // Will trigger `EBADF` from `btf_get_by_fd()` https://elixir.bootlin.com/linux/v5.2/source/kernel/bpf/btf.c#L3428
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
        // We aim to intentionally trigger `ENOTSUPP` by setting an invalid, non-zero
        // `btf_vmlinux_value_type_id`. Negative support produce `EINVAL` instead.
        MapType::StructOps => u.btf_vmlinux_value_type_id = 1,
        // arena required to be mmapable: https://elixir.bootlin.com/linux/v6.9/source/kernel/bpf/arena.c#L103
        MapType::Arena => u.map_flags = BPF_F_MMAPABLE,
        _ => {}
    }

    // SAFETY: BPF_MAP_CREATE returns a new file descriptor.
    let io_error = match unsafe { fd_sys_bpf(bpf_cmd::BPF_MAP_CREATE, &mut attr) } {
        Ok(_) => return Ok(true),
        Err(io_error) => io_error,
    };

    // sk_storage, struct_ops, inode_storage, task_storage, & cgrp_storage requires further
    // examination to verify support.
    match io_error.raw_os_error() {
        Some(EINVAL) => Ok(false),
        // These types use fields that may not exist at the kernel's current version.
        // Supplying `bpf_attr` fields unknown to the kernel triggers `E2BIG` from
        // `bpf_check_uarg_tail_zero()` https://elixir.bootlin.com/linux/v4.18/source/kernel/bpf/syscall.c#L71.
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
        // For these types, `EBADF` from `btf_get_by_fd()` https://elixir.bootlin.com/linux/v5.2/source/kernel/bpf/btf.c#L3428
        // indicates that map_create advanced far enough in the validation to recognize the type
        // before being rejected.
        // Otherwise, negative support produces `EINVAL`, meaning it was immediately rejected.
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
        // `ENOTSUPP` from `bpf_struct_ops_map_alloc()` https://elixir.bootlin.com/linux/v5.6/source/kernel/bpf/bpf_struct_ops.c#L557
        // indicates that map_create advanced far enough in the validation to recognize the type
        // before being rejected.
        // Otherwise, negative support produces `EINVAL`, meaning it was immediately rejected.
        Some(524) if map_type == MapType::StructOps => Ok(true),
        _ => Err(SyscallError {
            call: "bpf_map_create",
            io_error,
        }),
    }
}

/// Whether `nr_map_ids` & `map_ids` fields in `bpf_prog_info` are supported.
pub(crate) fn is_prog_info_map_ids_supported() -> Result<bool, ProgramError> {
    let fd = with_trivial_prog(ProgramType::SocketFilter, |attr| {
        bpf_prog_load(attr).map_err(|io_error| {
            ProgramError::SyscallError(SyscallError {
                call: "bpf_prog_load",
                io_error,
            })
        })
    })?;
    // SAFETY: all-zero byte-pattern valid for `bpf_prog_info`
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    info.nr_map_ids = 1;

    probe_bpf_info(fd, info).map_err(ProgramError::from)
}

/// Tests whether `bpf_prog_info.gpl_compatible` field is supported.
pub(crate) fn is_prog_info_license_supported() -> Result<bool, ProgramError> {
    let fd = with_trivial_prog(ProgramType::SocketFilter, |attr| {
        bpf_prog_load(attr).map_err(|io_error| {
            ProgramError::SyscallError(SyscallError {
                call: "bpf_prog_load",
                io_error,
            })
        })
    })?;
    // SAFETY: all-zero byte-pattern valid for `bpf_prog_info`
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    info.set_gpl_compatible(1);

    probe_bpf_info(fd, info).map_err(ProgramError::from)
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
