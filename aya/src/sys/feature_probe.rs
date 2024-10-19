//! Probes and identifies available eBPF features supported by the host kernel.

use aya_obj::btf::{Btf, BtfKind};
use libc::{E2BIG, EINVAL};

use super::{SyscallError, bpf_prog_load, with_trivial_prog};
use crate::programs::{ProgramError, ProgramType};

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

    let mut verifier_log = [0_u8; 136];
    // First aim for a valid bpf_prog_load using these funcs for tracing & lsm.
    // If symbols can't be retrieved from BTF, then leave unset and defer to verifier logs.
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
            // Use verifier log to detect support if loading fails.
            // Loading *may* fail for tracing & lsm if func symbols cannot be found in BTF.
            // Loading for extension is intentionally expected to fail.
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
                    // When `attach_btf_id` is unset for types that require it, the following
                    // message is written to logs.
                    // Message comes from `check_attach_btf_id()` https://elixir.bootlin.com/linux/v5.5/source/kernel/bpf/verifier.c#L9535,
                    // or `bpf_check_attach_target()` https://elixir.bootlin.com/linux/v5.9/source/kernel/bpf/verifier.c#L10849 on later versions
                    let supported = matches!(
                        program_type,
                        ProgramType::Tracing | ProgramType::Extension | ProgramType::Lsm
                            if verifier_log.starts_with(b"Tracing programs must provide btf_id"));
                    Ok(supported)
                }
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
