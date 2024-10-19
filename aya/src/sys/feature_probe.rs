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
